/*
 * Copyright (c) 2025, The Authors. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.github.csaf.sbom.matching.properties

import io.github.csaf.sbom.matching.*
import io.github.csaf.sbom.schema.generated.Csaf
import protobom.protobom.Node

sealed class ProductVersion {

    abstract fun matchingConfidence(other: ProductVersion): MatchingConfidence

    data class Fixed(val version: String) : ProductVersion() {
        override fun matchingConfidence(other: ProductVersion): MatchingConfidence {
            return when (other) {
                is Fixed -> if (version == other.version) DefiniteMatch else DefinitelyNoMatch
                is Range -> if (other.range.contains(version)) DefiniteMatch else DefinitelyNoMatch
                Unspecified -> MatchPackageNoVersion
            }
        }
    }

    data class Range(val range: Vers) : ProductVersion() {
        override fun matchingConfidence(other: ProductVersion): MatchingConfidence {
            return when (other) {
                is Fixed -> if (range.contains(other.version)) DefiniteMatch else DefinitelyNoMatch
                is Range ->
                    if (range.overlapsWith(other.range)) DefiniteMatch else DefinitelyNoMatch
                Unspecified -> MatchPackageNoVersion
            }
        }
    }

    object Unspecified : ProductVersion() {
        override fun matchingConfidence(other: ProductVersion): MatchingConfidence {
            return MatchPackageNoVersion
        }
    }
}

/** A property that represents a product version. */
class ProductVersionProperty(value: ProductVersion, source: PropertySource) :
    Property<ProductVersion>(value, source) {
    override fun confidenceMatching(other: Property<ProductVersion>): MatchingConfidence {
        return this.value.matchingConfidence(other.value)
    }
}

/** A little helper extension to convert a [ProductVersion] to a [ProductVersionProperty]. */
fun ProductVersion.toProperty(source: PropertySource): ProductVersionProperty {
    return ProductVersionProperty(this, source)
}

/**
 * A little helper extension to convert a string to a [ProductVersion.Fixed].
 *
 * This will also sanitize the version string by removing leading 'v' characters and trailing zeros.
 */
fun String.toProductVersion(): ProductVersion.Fixed {
    val version = this

    // In an effort to sanitize the version strings, we remove training zeros and leading 'v'
    // characters
    val versionSanitized = version.trimStart('v', ' ', '\t')

    return ProductVersion.Fixed(versionSanitized)
}

/** A little helper extension to convert a [Vers] to a [ProductVersion.Range]. */
fun Vers.toProductVersion(): ProductVersion.Range {
    return ProductVersion.Range(this)
}

/**
 * The [ProductVersionPropertyProvider] is a [PropertyProvider] that provides the name of a product
 * as a [ProductVersionProperty].
 *
 * It extracts the version from the [VulnerableProduct.branches], [Cpe] or [Purl] and returns it as
 * a [ProductVersionProperty].
 */
object ProductVersionPropertyProvider : PropertyProvider<ProductVersionProperty> {
    override fun provideProperty(vulnerable: VulnerableProduct): ProductVersionProperty? {
        val version =
            vulnerable.branches.firstOrNull { it.category == Csaf.Category3.product_version }?.name

        // We only consider version ranges if the version is not set
        if (version == null) {
            val versionRange =
                vulnerable.branches
                    .firstOrNull { it.category == Csaf.Category3.product_version_range }
                    ?.name
            return versionRange
                ?.let { parseVers(it) }
                ?.toProductVersion()
                ?.toProperty(PropertySource.OTHER)
        }

        return version.toProductVersion().toProperty(PropertySource.OTHER)
    }

    override fun provideProperty(node: Node): ProductVersionProperty? {
        return node.version.ifBlank { null }?.toProductVersion()?.toProperty(PropertySource.OTHER)
    }

    override fun provideProperty(cpe: Cpe): ProductVersionProperty? {
        return cpe.getVersion().toProductVersion().toProperty(PropertySource.CPE)
    }

    override fun provideProperty(purl: Purl): ProductVersionProperty? {
        return purl.getVersion()?.toProductVersion()?.toProperty(PropertySource.PURL)
    }
}
