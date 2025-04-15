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
package io.csaf.matching

import io.csaf.schema.generated.Csaf
import protobom.protobom.Document
import protobom.protobom.Node
import protobom.protobom.NodeList

/** A database of SBOMs represented as a list of [SBOM] instances. */
typealias SBOMDatabase = List<Document>

/** A single Bill-of-Materials (SBOM). */
typealias SBOM = Document

/** A single component in an [SBOM]. */
typealias SBOMComponent = Node

/**
 * Matcher for matching an SBOM database with provided CSAF documents.
 *
 * @property documents The CSAF security advisories used by this matcher.
 * @property threshold The default threshold required for a match to be included.
 */
class Matcher(val documents: List<Csaf>, val threshold: Float = 0.5f) {
    var products = listOf<ProductWithBranches>()

    /**
     * The constructor checks that the given threshold is within its bounds and then extracts all
     * relevant information for comparison from the given CSAF documents for faster matching.
     */
    init {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }
        products = documents.flatMap { it.gatherProductsWithBranches() }
    }

    /**
     * Matches the provided SBOM database with the CSAF advisories and determines whether they meet
     * specific criteria.
     *
     * @param database A list of SBOMs represented by [SBOM] instances.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of [Match] objects between the SBOM node and the CSAF advisories.
     */
    fun matchDatabase(database: SBOMDatabase, threshold: Float = this.threshold): Set<Match> {
        val matches = mutableSetOf<Match>()
        for (document in database) {
            matches += match(document, threshold)
        }
        return matches
    }

    /**
     * Matches the provided SBOM with the CSAF advisories and determines whether they meet specific
     * criteria.
     *
     * @param sbom The SBOM represented by a [SBOM] instance.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of [Match] objects between the SBOM node and the CSAF advisories.
     */
    fun match(sbom: SBOM, threshold: Float = this.threshold): Set<Match> =
        internalMatch((sbom.nodeList ?: NodeList()).nodes, threshold)

    /**
     * Matches the provided SBOM component with the CSAF advisories and determines whether they meet
     * specific criteria.
     *
     * @param component The SBOM node represented by a [Node] instance.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of [Match] objects between the SBOM node and the CSAF advisories.
     */
    fun matchComponent(component: SBOMComponent, threshold: Float = this.threshold) =
        internalMatch(listOf(component), threshold)

    /**
     * Matches the provided SBOM components with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param components A list of SBOM components represented by [SBOMComponent] instances.
     * @param threshold The minimum threshold required for a match to be included.
     * @return A list of CSAF documents matching the given nodes, along with resp. match scores.
     */
    private fun internalMatch(components: List<SBOMComponent>, threshold: Float): Set<Match> {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }

        val matches = mutableSetOf<Match>()

        // Loop through all nodes
        for (component in components) {
            // Loop through all affected products
            for (vulnerableProduct in products) {
                // Check if the component is affected by the product
                val confidence = matchProperties(vulnerableProduct, component)
                // If the confidence is above the threshold, add it to the matches
                if (confidence.value >= threshold) {
                    matches +=
                        Match(
                            vulnerableProduct.advisory,
                            vulnerableProduct.product,
                            component,
                            confidence,
                        )
                }
            }
        }

        return matches
    }
}
