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
            }
        }
    }

    data class Range(val range: Vers) : ProductVersion() {
        override fun matchingConfidence(other: ProductVersion): MatchingConfidence {
            return when (other) {
                is Fixed -> if (range.contains(other.version)) DefiniteMatch else DefinitelyNoMatch
                is Range ->
                    if (range.overlapsWith(other.range)) DefiniteMatch else DefinitelyNoMatch
            }
        }
    }
}

/**
 * A property that represents a product version.
 *
 * The confidence of a match (see [confidenceMatching]) is determined by comparing the version
 * values.
 * - If the version is a fixed version and the other is a fixed version, the confidence is
 *   [DefiniteMatch] if the versions are equal, otherwise [DefinitelyNoMatch].
 * - If the version is a fixed version and the other is a range, the confidence is [DefiniteMatch]
 *   if the version is in the range, otherwise [DefinitelyNoMatch].
 * - If the version is a range and the other is a fixed version, the confidence is [DefiniteMatch]
 *   if the version is in the range, otherwise [DefinitelyNoMatch].
 * - If the version is a range and the other is a range, the confidence is [DefiniteMatch] if the
 *   ranges overlap, otherwise [DefinitelyNoMatch].
 */
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

/**
 * A little helper extension to convert a [Vers] to a [ProductVersionProperty] (using
 * [ProductVersion.Range]).
 */
fun Vers.toProductProperty(source: PropertySource): ProductVersionProperty {
    return ProductVersionProperty(ProductVersion.Range(this), source)
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
            return versionRange?.let { parseVers(it) }?.toProductProperty(PropertySource.OTHER)
        }

        return version.toProductVersion().toProperty(PropertySource.OTHER)
    }

    override fun provideProperty(node: Node): ProductVersionProperty? {
        return if (node.version == "") {
            null
        } else {
            node.version.toProductVersion().toProperty(PropertySource.OTHER)
        }
    }

    override fun provideProperty(cpe: Cpe): ProductVersionProperty? {
        return cpe.getVersion().toProductVersion().toProperty(PropertySource.CPE)
    }

    override fun provideProperty(purl: Purl): ProductVersionProperty? {
        val version = purl.getVersion()?.toProductVersion()
        return version?.toProperty(PropertySource.PURL)
    }
}
