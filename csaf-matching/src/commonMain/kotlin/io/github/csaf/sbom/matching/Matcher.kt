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

import io.github.csaf.sbom.matching.cpe.Cpe
import io.github.csaf.sbom.matching.cpe.parseCpe
import io.github.csaf.sbom.matching.purl.Purl
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.tests.mapBranchesNotNull
import protobom.protobom.Document
import protobom.protobom.SoftwareIdentifierType

/**
 * Matcher for matching SBOM documents with provided CSAF documents.
 *
 * @property docs The CSAF documents used by this matcher.
 * @property threshold The default threshold required for a match to be included.
 */
class Matcher(val docs: List<Csaf>, val threshold: Float = 0.5f) {
    val purlMap = mutableMapOf<String, MutableSet<FastHash<Csaf>>>()
    val cpeMap = mutableMapOf<Cpe, MutableSet<FastHash<Csaf>>>()

    /**
     * The constructor checks that the given threshold is within its bounds and then extracts all
     * relevant information for comparison from the given CSAF documents for faster matching.
     */
    init {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }
        docs.forEach { doc ->
            // Cache all canonicalized PURLs
            doc.product_tree
                .mapBranchesNotNull {
                    it.product?.product_identification_helper?.purl?.let {
                        Purl(it.toString()).canonicalize()
                    }
                }
                .forEach {
                    purlMap.computeIfAbsent(it) { hashSetOf<FastHash<Csaf>>() }.add(FastHash(doc))
                }
            // Cache all CPEs, start with full product names
            doc.product_tree?.full_product_names?.forEach {
                it.product_identification_helper?.cpe?.let {
                    cpeMap
                        .computeIfAbsent(parseCpe(it)) { hashSetOf<FastHash<Csaf>>() }
                        .add(FastHash(doc))
                }
            }
            // Collect more CPEs from product tree (branches)
            doc.product_tree
                .mapBranchesNotNull {
                    it.product?.product_identification_helper?.cpe?.let { parseCpe(it) }
                }
                .forEach {
                    cpeMap.computeIfAbsent(it) { hashSetOf<FastHash<Csaf>>() }.add(FastHash(doc))
                }
        }
    }

    /**
     * Matches the provided SBOM document with the CSAF documents and determines whether they meet
     * specific criteria.
     *
     * @param sbom The SBOM document represented by a protobom.protobom.Document instance.
     * @param threshold The minimum threshold required for a match to be included, defaults to the
     *   value of this [Matcher].
     * @return A list of CSAF documents matching the given SBOM, along with resp. match scores.
     */
    fun match(sbom: Document, threshold: Float = this.threshold): List<Match> {
        require(threshold in 0.0..1.0) { "Threshold must be in the interval [0.0; 1.0]." }
        val matches = hashMapOf<FastHash<Csaf>, Float>()
        // If given threshold is 0.0, all documents will be "matched".
        if (threshold == 0.0f) {
            docs.forEach { matches[FastHash(it)] = 0.0f }
        }
        sbom.nodeList?.let { nl ->
            nl.nodes.forEach {
                it.identifiers.forEach { (identifier, value) ->
                    when (identifier) {
                        // We consider PURL matches as perfect match (score 1.0).
                        SoftwareIdentifierType.PURL.value -> {
                            val cPurl = Purl(value).canonicalize()
                            purlMap[cPurl]?.let { it.map { matches[it] = 1.0f } }
                        }
                        // We consider CPE matches as perfect match (score 1.0).
                        SoftwareIdentifierType.CPE22.value,
                        SoftwareIdentifierType.CPE23.value -> {
                            val cCpe = parseCpe(value)
                            cpeMap.forEach { (cpe, csafSet) ->
                                if (cpe.matches(cCpe)) {
                                    csafSet.map { matches[it] = 1.0f }
                                }
                            }
                        }
                    }
                }
            }
        }
        return matches.map { Match(it.key.o, it.value) }
    }
}
