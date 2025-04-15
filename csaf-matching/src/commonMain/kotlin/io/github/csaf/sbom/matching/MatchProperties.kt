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
package io.github.csaf.sbom.matching

import io.github.csaf.sbom.matching.properties.CpeProperty
import io.github.csaf.sbom.matching.properties.CpePropertyProvider
import io.github.csaf.sbom.matching.properties.ProductNameProperty
import io.github.csaf.sbom.matching.properties.ProductNamePropertyProvider
import io.github.csaf.sbom.matching.properties.ProductVersionProperty
import io.github.csaf.sbom.matching.properties.ProductVersionPropertyProvider
import io.github.csaf.sbom.matching.properties.Property
import io.github.csaf.sbom.matching.properties.PropertyProvider
import io.github.csaf.sbom.matching.properties.PurlPropertyProvider
import io.github.csaf.sbom.matching.properties.VendorProperty
import io.github.csaf.sbom.matching.properties.VendorPropertyProvider
import io.github.csaf.sbom.matching.properties.gatherComponentProperties
import io.github.csaf.sbom.matching.properties.gatherVulnerableProperties
import protobom.protobom.Node

/**
 * This is the core function of the [Matcher]. It matches a vulnerable product against a component
 * by comparing different [Property] objects in a defined order.
 * - First, it matches the vendor name (see [VendorProperty] / [VendorPropertyProvider])
 * - Then, it matches the product name (see [ProductNameProperty] / [ProductNamePropertyProvider])
 * - Finally, it matches the product version (see [ProductVersionProperty] /
 *   [ProductVersionPropertyProvider])
 */
fun matchProperties(vulnerable: ProductWithBranches, node: Node): MatchingConfidence {
    // First level of priority: CPE, Purl. If either of these is set, we can directly return with
    // high confidence
    if (vulnerable.cpe != null) {
        var match = matchProperty(CpePropertyProvider, vulnerable, node)
        if (match == DefiniteMatch) {
            return match
        }
    } else if (vulnerable.purl != null) {
        var match = matchProperty(PurlPropertyProvider, vulnerable, node)
        if (match == DefiniteMatch) {
            return match
        }
    }

    // Next, we try to match on the category values.
    //
    // First, match on vendor name. If we do not have a match on the vendor, we can still continue,
    // albeit with a lower confidence
    var match = matchProperty(VendorPropertyProvider, vulnerable, node, MatchWithoutVendor)

    // Next, we try to match on the product name. If we do not have a match on the product name, we
    // can exit here
    match *= matchProperty(ProductNamePropertyProvider, vulnerable, node)
    if (match == DefinitelyNoMatch) {
        return DefinitelyNoMatch
    }

    // Next, we try to match on the product version. If we do not have a match on the product
    // version, we can still continue albeit with a lower confidence
    match *= matchProperty(ProductVersionPropertyProvider, vulnerable, node, MatchPackageNoVersion)

    return match
}

/**
 * Matches a certain property (of type [PropertyType]) from a vulnerable product against a property
 * from a component. The property is provided by a [ProviderType].
 *
 * The matching is done by comparing the properties with each other and returning the highest
 * confidence. The idea is that we can potentially match the properties coming from different
 * sources. For example, we might be able to obtain a [DefiniteMatch] on a [ProductNameProperty] by
 * matching their names in an [CpeProperty] (e.g., `linux_kernel`) and a
 * [CaseInsensitiveIgnoreDashMatch] when comparing the human-readable name (`Linux Kernel`) against
 * it. In this case, we only return the [DefiniteMatch].
 *
 * It follows the following steps:
 * - Gather the properties from the vulnerable product (using [gatherVulnerableProperties])
 * - Gather the properties from the component (using [gatherComponentProperties])
 * - Calculate a confidence for each possible pair of properties and store them in a list
 * - Return the highest confidence from the list
 *
 * @param provider The provider that provides the properties.
 * @param vulnerable The vulnerable product to match against.
 * @param node The component to match against.
 * @param default The default confidence to return if no match is found.
 */
fun <
    RawType,
    PropertyType : Property<RawType>,
    ProviderType : PropertyProvider<PropertyType>,
> matchProperty(
    provider: ProviderType,
    vulnerable: ProductWithBranches,
    node: Node,
    default: MatchingConfidence = DefinitelyNoMatch,
): MatchingConfidence {
    // Gather the properties from the vulnerable product
    val vulnerableProperties = provider.gatherVulnerableProperties(vulnerable)

    // Gather the properties from the component
    val componentProperties = provider.gatherComponentProperties(node)

    // Try to match the properties
    val possibleMatches = mutableListOf<MatchingConfidence>()
    for (vulnerableProperty in vulnerableProperties.values) {
        for (componentProperty in componentProperties.values) {
            val match = vulnerableProperty.confidenceMatching(componentProperty)
            possibleMatches += match
        }
    }

    // Calculate the highest one
    return (possibleMatches.maxByOrNull { it.value } ?: default)
}
