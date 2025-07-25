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
package io.csaf.matching

import io.csaf.schema.generated.Csaf
import io.csaf.validation.tests.affectedProducts
import io.csaf.validation.tests.notAffectedProducts

/**
 * A data class representing a match between an [Csaf.Product] to an [SBOMComponent] with given
 * [MatchingConfidence].
 *
 * @property document The matched CSAF document.
 * @property product The product from the CSAF document.
 * @property matchedComponent The affected component from the SBOM document.
 * @property confidence The confidence score of the match.
 * @constructor Creates match between CSAF document and (parts of) an SBOM with a given score.
 */
data class Match(
    val document: Csaf,
    val product: Csaf.Product,
    val matchedComponent: SBOMComponent,
    val confidence: MatchingConfidence,
)

/**
 * Returns a list of vulnerabilities from the CSAF document that are associated with the product in
 * this match through [affectedProducts].
 *
 * @return A list of [Csaf.Vulnerability] objects that have [affectedProducts] listed in this match.
 */
fun Match.vulnerabilitiesWithAffectedProduct(): List<Csaf.Vulnerability> {
    return document.vulnerabilities?.filter {
        it.affectedProducts.any { productId -> product.product_id == productId }
    } ?: emptyList()
}

/**
 * Returns a list of vulnerabilities from the CSAF document that are associated with the product in
 * this match through [notAffectedProducts].
 *
 * @return A list of [Csaf.Vulnerability] objects that have [notAffectedProducts] listed in this
 *   match.
 */
fun Match.vulnerabilitiesWithNotAffectedProduct(): List<Csaf.Vulnerability> {
    return document.vulnerabilities?.filter {
        it.notAffectedProducts.any { productId -> product.product_id == productId }
    } ?: emptyList()
}
