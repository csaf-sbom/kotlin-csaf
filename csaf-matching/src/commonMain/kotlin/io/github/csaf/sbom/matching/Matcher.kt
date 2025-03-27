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

import io.github.csaf.sbom.matching.cpe.CPEMatchingTask
import io.github.csaf.sbom.matching.purl.MatchingConfidence
import io.github.csaf.sbom.matching.purl.PurlMatchingTask
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.tests.affectedProducts
import io.github.csaf.sbom.validation.tests.mapBranchesNotNull
import protobom.protobom.Document
import protobom.protobom.Node
import protobom.protobom.NodeList

/**
 * This is utility class populated by the [Csaf.Branche] so that we have a nullable product and an
 * additional selector (e.g., version) based on [Csaf.Branche.category].
 */
data class ProductWithSelector(
    val product: Csaf.Product,
    val additionalSelector: Csaf.Category3,
    val selectorValue: String,
)

/**
 * Matcher for matching SBOM documents with a provided CSAF document.
 *
 * @property doc The CSAF document used by this matcher.
 * @property threshold The default threshold required for a match to be included.
 */
class Matcher(val doc: Csaf, val threshold: Float = 0.5f) {
    var affectedProducts = listOf<ProductWithSelector>()
    var tasks = listOf<MatchingTask>()

    /**
     * The constructor checks that the given threshold is within its bounds and then extracts all
     * relevant information for comparison from the given CSAF documents for faster matching.
     */
    init {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }
        val productIds = doc.vulnerabilities?.flatMap { vuln -> vuln.affectedProducts } ?: listOf()
        val affectedProductIds = productIds

        val test = doc.product_tree.mapBranchesNotNull(predicate = null) { Pair(it, it) }

        affectedProducts =
            doc.product_tree.mapBranchesNotNull({
                it.product != null && affectedProductIds.contains(it.product?.product_id) == true
            }) {
                it.product?.let { product -> ProductWithSelector(product, it.category, it.name) }
            }

        tasks = listOf<MatchingTask>(CPEMatchingTask, PurlMatchingTask, NameMatchingTask)
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

        val matches = mutableMapOf<Node, Match>()
        // Loop through all matching tasks
        for (task in tasks) {
            // Loop through all nodes
            for (node in nodes) {
                // Loop through all affected products
                for (affectedProduct in affectedProducts) {
                    // Check if the node is affected by the product
                    val confidence = task.match(affectedProduct, node)
                    // If the confidence is above the threshold, add it to the matches (unless we
                    // already have a higher confidence match)
                    if (confidence.value >= threshold) {
                        val existing = matches[node]
                        if (existing != null && existing.confidence.value >= confidence.value) {
                            continue
                        }
                        matches[node] = Match(doc, affectedProduct, node, confidence)
                    }
                }
            }
        }

        return matches.values.toSet()
    }
}

interface MatchingTask {
    fun match(vulnerable: ProductWithSelector, component: Node): MatchingConfidence
}
