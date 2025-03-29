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
package io.github.csaf.sbom.matching.provider

import io.github.csaf.sbom.matching.DefiniteMatch
import io.github.csaf.sbom.matching.MatchingConfidence
import io.github.csaf.sbom.matching.VulnerableProduct
import io.github.csaf.sbom.matching.cpe.Cpe
import io.github.csaf.sbom.matching.cpe.cpe
import io.github.csaf.sbom.matching.properties.Property
import io.github.csaf.sbom.matching.properties.StringProperty
import io.github.csaf.sbom.matching.properties.toProperty
import io.github.csaf.sbom.matching.purl.Purl
import io.github.csaf.sbom.matching.purl.purl
import io.github.csaf.sbom.schema.generated.Csaf
import protobom.protobom.Node

enum class PropertySource {
    PURL,
    CPE,
    OTHER,
}

/**
 * This interface is used to provide a property one can "match" against. This can be for example a
 * name or a version.
 *
 * The property is (usually) extracted out of a [VulnerableProduct] in the [provideProperty] method.
 */
interface PropertyProvider<T : Property<*>> {

    fun provideProperty(vulnerable: VulnerableProduct): T?

    fun provideProperty(node: Node): T?

    fun provideProperty(cpe: Cpe): T?

    fun provideProperty(purl: Purl): T?
}

/**
 * The [VendorProvider] is a [PropertyProvider] that provides the vendor of a product as a
 * [StringProperty].
 */
object VendorProvider : PropertyProvider<StringProperty> {
    override fun provideProperty(vulnerable: VulnerableProduct): StringProperty? {
        return vulnerable.branches
            .firstOrNull { it.category == Csaf.Category3.vendor }
            ?.name
            ?.toProperty(PropertySource.OTHER)
    }

    override fun provideProperty(node: Node): StringProperty? {
        return null
    }

    override fun provideProperty(cpe: Cpe): StringProperty? {
        return cpe.getVendor().toProperty(PropertySource.CPE)
    }

    override fun provideProperty(purl: Purl): StringProperty? {
        return null
    }
}

/**
 * This extension function is used to gather all properties from a [PropertyProvider] for a
 * [VulnerableProduct].
 *
 * It returns a [Map] with the [PropertySource] as key and the property as value.
 */
fun <T : Property<*>> PropertyProvider<T>.gatherVulnerableProperties(
    vulnerable: VulnerableProduct
): Map<PropertySource, T> {
    val properties = mutableMapOf<PropertySource, T>()
    this.provideProperty(vulnerable)?.let { properties[PropertySource.OTHER] = it }
    vulnerable.cpe
        ?.let { cpe -> this.provideProperty(cpe) }
        ?.let { properties[PropertySource.CPE] = it }
    vulnerable.purl
        ?.let { purl -> this.provideProperty(purl) }
        ?.let { properties[PropertySource.PURL] = it }

    return properties
}

/**
 * This extension function is used to gather all properties from a [PropertyProvider] for a [Node]
 * (component).
 *
 * It returns a [Map] with the [PropertySource] as key and the property as value.
 */
fun <T : Property<*>> PropertyProvider<T>.gatherComponentProperties(
    node: Node
): Map<PropertySource, T> {
    val properties = mutableMapOf<PropertySource, T>()
    this.provideProperty(node)?.let { properties[PropertySource.OTHER] = it }
    node.cpe?.let { cpe -> this.provideProperty(cpe) }?.let { properties[PropertySource.CPE] = it }
    node.purl
        ?.let { purl -> this.provideProperty(purl) }
        ?.let { properties[PropertySource.PURL] = it }

    return properties
}

class ProviderBasedMatcher() {
    fun match(vulnerable: VulnerableProduct, node: Node): MatchingConfidence {
        // First, try to match the vendor
        val vendorProperty = VendorProvider.provideProperty(vulnerable)
        return DefiniteMatch
    }
}
