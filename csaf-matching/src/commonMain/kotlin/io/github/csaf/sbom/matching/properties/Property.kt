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

import io.github.csaf.sbom.matching.Cpe
import io.github.csaf.sbom.matching.MatchingConfidence
import io.github.csaf.sbom.matching.Purl
import io.github.csaf.sbom.matching.VulnerableProduct
import io.github.csaf.sbom.matching.cpe
import io.github.csaf.sbom.matching.purl
import protobom.protobom.Node

enum class PropertySource {
    PURL,
    CPE,
    OTHER,
}

/**
 * This interface is used to provide a property one can "match" against. This can be for example
 * something string-based (such as name) or others structures like a software identifier.
 */
abstract class Property<T>(val value: T, val source: PropertySource) {

    /**
     * This method is used to compare the property with another property of the same type. Instead
     * of a [Boolean] it must return a [MatchingConfidence] that expresses how confident the match
     * is.
     *
     * Note: For the matching, the implementer MUST assume that "this" is always the property that
     * belongs to the vulnerable product and [other] is the property that belongs to the
     * (potentially) affected component.
     */
    abstract fun confidenceMatching(other: Property<T>): MatchingConfidence

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Property<*>) return false

        if (value != other.value) return false
        if (source != other.source) return false

        return true
    }

    override fun hashCode(): Int {
        var result = value?.hashCode() ?: 0
        result = 31 * result + source.hashCode()
        return result
    }

    override fun toString(): String {
        return "Property(value=$value, source=$source)"
    }
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
