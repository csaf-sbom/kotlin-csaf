/*
 * Copyright (c) 2024, The Authors. All rights reserved.
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

import io.github.csaf.sbom.matching.properties.*
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.tests.affectedProducts
import protobom.protobom.Document
import protobom.protobom.Node
import protobom.protobom.NodeList

/**
 * Matcher for matching SBOM documents with a provided CSAF document.
 *
 * @property doc The CSAF document used by this matcher.
 * @property threshold The default threshold required for a match to be included.
 */
class Matcher(val doc: Csaf, val threshold: Float = 0.5f) {
    var affectedProducts = listOf<VulnerableProduct>()

    /**
     * The constructor checks that the given threshold is within its bounds and then extracts all
     * relevant information for comparison from the given CSAF documents for faster matching.
     */
    init {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }
        val productIds = doc.vulnerabilities?.flatMap { vuln -> vuln.affectedProducts } ?: listOf()
        val affectedProductIds = productIds

        val products = doc.product_tree.gatherVulnerableProducts()

        affectedProducts = products.filter { it.product.product_id in affectedProductIds }
    }

    /**
     * Matches the provided SBOM node with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param sbomNode The SBOM node represented by a [Node] instance.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of CSAF documents matching the given node, along with resp. match scores.
     */
    fun match(sbomNode: Node, threshold: Float = this.threshold) =
        match(listOf(sbomNode), threshold)

    /**
     * Matches the provided SBOM document with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param sbomDocument The SBOM document represented by a [Document] instance.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of CSAF documents matching the given document, along with resp. match scores.
     */
    fun matchAll(sbomDocument: Document, threshold: Float = this.threshold): Set<Match> =
        match((sbomDocument.nodeList ?: NodeList()).nodes, threshold)

    /**
     * Matches the provided SBOM nodes with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param nodes A list of SBOM nodes represented by [Node] instances.
     * @param threshold The minimum threshold required for a match to be included.
     * @return A list of CSAF documents matching the given nodes, along with resp. match scores.
     */
    private fun match(nodes: List<Node>, threshold: Float): Set<Match> {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }

        val matches = mutableSetOf<Match>()

        // Loop through all nodes
        for (node in nodes) {
            // Loop through all affected products
            for (affectedProduct in affectedProducts) {
                // Check if the node is affected by the product
                val confidence = matchProperties(affectedProduct, node)
                // If the confidence is above the threshold, add it to the matches
                if (confidence.value >= threshold) {
                    matches += Match(doc, affectedProduct, node, confidence)
                }
            }
        }

        return matches
    }
}

/**
 * This is the core function of the [Matcher]. It matches a vulnerable product against a component
 * by comparing different [Property] objects in a defined order.
 * - First, it matches the vendor name (see [VendorProperty] / [VendorPropertyProvider])
 * - Then, it matches the product name (see [ProductNameProperty] / [ProductNamePropertyProvider])
 * - Finally, it matches the product version (see [ProductVersionProperty] /
 *   [ProductVersionPropertyProvider])
 */
fun matchProperties(vulnerable: VulnerableProduct, node: Node): MatchingConfidence {
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
    vulnerable: VulnerableProduct,
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
