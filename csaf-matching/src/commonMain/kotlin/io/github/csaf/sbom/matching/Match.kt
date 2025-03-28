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

import io.github.csaf.sbom.matching.cpe.Cpe
import io.github.csaf.sbom.matching.cpe.parseCpe
import io.github.csaf.sbom.matching.purl.MatchingConfidence
import io.github.csaf.sbom.matching.purl.Purl
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Product
import io.github.csaf.sbom.validation.tests.plusAssign
import protobom.protobom.Node

/**
 * A utility class for a [Product] and a list of [Csaf.Branche]s that define the "path" from the
 * roof of the [Csaf.ProductTree] to the [Product]
 */
data class ProductInfo(var product: Product, var branches: List<Csaf.Branche>) {
    val cpe: Cpe? = product.product_identification_helper?.cpe?.let { parseCpe(it) }
    val purl: Purl? = product.product_identification_helper?.purl?.toString()?.let { Purl(it) }
}

fun Csaf.ProductTree?.gatherProductsWithBranches(
    predicate: ((Product) -> Boolean)? = null
): List<ProductInfo> {
    val products = mutableListOf<ProductInfo>()
    val worklist = mutableListOf<List<Csaf.Branche>>()
    val alreadySeen = mutableSetOf<Csaf.Branche>()

    // Start with this branches
    worklist += this?.branches

    while (worklist.isNotEmpty()) {
        val currentPath = worklist.maxBy { it.size }
        worklist.remove(currentPath)

        val currentBranch = currentPath.last()
        alreadySeen += currentBranch

        val nextBranches = currentBranch.branches
        for (nextBranch in nextBranches ?: listOf()) {
            // We arrived at a product node, we are finished
            val product = nextBranch.product
            if (product != null && predicate?.invoke(product) != false) {
                val productInfo =
                    ProductInfo(product = product, branches = currentPath + nextBranch)
                products.add(productInfo)
                // Done with this path
                continue
            }

            // Otherwise, continue
            worklist.add(currentPath + nextBranch)
        }
    }

    return products
}

/**
 * A data class representing a match between an [Csaf.Product] to a SBOM [Node] with given
 * [MatchingConfidence].
 *
 * @property csaf The matched CSAF document.
 * @property affectedProduct The affected product from the CSAF document.
 * @property affectedComponent The affected component from the SBOM document.
 * @property confidence The confidence score of the match.
 * @constructor Creates CSAF-SBOM-match with given score.
 */
data class Match(
    val csaf: Csaf,
    val affectedProduct: ProductInfo,
    val affectedComponent: Node,
    val confidence: MatchingConfidence,
)
