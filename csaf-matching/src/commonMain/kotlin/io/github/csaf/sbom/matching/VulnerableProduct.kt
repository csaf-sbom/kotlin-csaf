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

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Product
import io.github.csaf.sbom.validation.tests.plusAssign

/**
 * A utility class for a [Product] and a list of [Csaf.Branche]s that define the "path" from the
 * roof of the [Csaf.ProductTree] to the [Product]
 */
data class VulnerableProduct(var product: Product, var branches: List<Csaf.Branche>) {
    val cpe: Cpe? = product.product_identification_helper?.cpe?.let { parseCpe(it) }
    val purl: Purl? = product.product_identification_helper?.purl?.let { Purl(it.toString()) }
}

fun Csaf.ProductTree?.gatherVulnerableProducts(
    predicate: ((Product) -> Boolean)? = null
): List<VulnerableProduct> {
    val products = mutableListOf<VulnerableProduct>()
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
                val vulnerableProduct =
                    VulnerableProduct(product = product, branches = currentPath + nextBranch)
                products.add(vulnerableProduct)
                // Done with this path
                continue
            }

            // Otherwise, continue
            worklist.add(currentPath + nextBranch)
        }
    }

    return products
}
