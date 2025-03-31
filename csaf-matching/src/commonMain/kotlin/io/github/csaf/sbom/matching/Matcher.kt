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

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.tests.affectedProducts
import protobom.protobom.Document
import protobom.protobom.Node
import protobom.protobom.NodeList

/**
 * Matcher for matching an SBOM advisories with a provided CSAF document.
 *
 * @property advisories The CSAF security advisories used by this matcher.
 * @property threshold The default threshold required for a match to be included.
 */
class Matcher(val advisories: List<Csaf>, val threshold: Float = 0.5f) {
    var vulnerableProducts = listOf<VulnerableProduct>()

    /**
     * The constructor checks that the given threshold is within its bounds and then extracts all
     * relevant information for comparison from the given CSAF documents for faster matching.
     */
    init {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }
        val productIds =
            advisories
                .mapNotNull { it.vulnerabilities?.flatMap { vuln -> vuln.affectedProducts } }
                .flatten()
        val affectedProductIds = productIds

        val products = advisories.flatMap { it.gatherVulnerableProducts() }

        vulnerableProducts = products.filter { it.product.product_id in affectedProductIds }
    }

    /**
     * Matches the provided SBOM component with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param node The SBOM node represented by a [Node] instance.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of [Match] objects between the SBOM node and the CSAF advisories.
     */
    fun matchSBOMComponent(node: Node, threshold: Float = this.threshold) = match(listOf(node), threshold)

    /**
     * Matches the provided SBOM document with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param document The SBOM document represented by a [Document] instance.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of [Match] objects between the SBOM node and the CSAF advisories.
     */
    fun matchSBOM(document: Document, threshold: Float = this.threshold): Set<Match> =
        match((document.nodeList ?: NodeList()).nodes, threshold)

    /**
     * Matches the provided SBOM database with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param database A list of SBOM documents represented by [Document] instances.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *  value of this [Matcher].
     * @return A list of [Match] objects between the SBOM node and the CSAF advisories.
     */
    fun matchSBOMDatabase(
        database: List<Document>,
        threshold: Float = this.threshold,
    ): Set<Match> {
        val matches = mutableSetOf<Match>()
        for (document in database) {
            matches += matchSBOM(document, threshold)
        }
        return matches
    }

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
            for (vulnerableProduct in vulnerableProducts) {
                // Check if the node is affected by the product
                val confidence = matchProperties(vulnerableProduct, node)
                // If the confidence is above the threshold, add it to the matches
                if (confidence.value >= threshold) {
                    matches +=
                        Match(
                            vulnerableProduct.advisory,
                            vulnerableProduct.product,
                            node,
                            confidence,
                        )
                }
            }
        }

        return matches
    }
}
