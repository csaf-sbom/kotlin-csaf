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
 * root of the [Csaf.ProductTree] to the [Product]
 */
data class ProductWithBranches(
    var advisory: Csaf,
    var product: Product,
    var branches: List<Csaf.Branche>,
) {
    val cpe: Cpe? = product.product_identification_helper?.cpe?.let { parseCpe(it) }
    val purl: Purl? = product.product_identification_helper?.purl?.let { Purl(it.toString()) }
}

/**
 * Gathers all [Product]s in the current document and their branches. The [predicate] is used to
 * filter the products. If it is null, all products are returned.
 *
 * The function traverses the product tree and collects all branches that lead to a product (leaf
 * nodes). It fills a list with [ProductWithBranches] objects, each containing the product and its
 * path in the tree.
 *
 * @param predicate A function that takes a [Product] and returns a Boolean. If null, all products
 *   are included.
 * @return A list of [ProductWithBranches] objects, each containing a product and its path in the
 *   tree.
 */
fun Csaf.gatherProductsWithBranches(
    predicate: ((Product) -> Boolean)? = null
): List<ProductWithBranches> {
    val products = mutableListOf<ProductWithBranches>()
    val worklist = mutableListOf<List<Csaf.Branche>>()
    val alreadySeen = mutableSetOf<Csaf.Branche>()

    // Start with this branches
    worklist += this.product_tree?.branches

    // Work until work-list is empty
    while (worklist.isNotEmpty()) {
        val currentPath = worklist.maxBy { it.size }
        worklist.remove(currentPath)

        // Jump to the "deepest" branch object
        val currentBranch = currentPath.last()

        // Add it to the already-seen, to avoid loops
        alreadySeen += currentBranch

        // Look at the next level of branches and loop through them
        val nextBranches = currentBranch.branches
        for (nextBranch in nextBranches ?: listOf()) {
            // We arrived at a product node, we are finished
            val product = nextBranch.product
            if (product != null && predicate?.invoke(product) != false) {
                val vulnerableProduct =
                    ProductWithBranches(
                        advisory = this,
                        product = product,
                        branches = currentPath + nextBranch,
                    )
                products.add(vulnerableProduct)
                // Done with this path
                continue
            }

            // Otherwise, continue down the tree
            worklist.add(currentPath + nextBranch)
        }
    }

    return products
}
