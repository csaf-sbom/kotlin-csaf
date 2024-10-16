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
package io.github.csaf.sbom.validation.tests

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Category3
import io.github.csaf.sbom.schema.generated.Csaf.Category4
import kotlin.test.Test
import kotlin.test.assertEquals

class ExtensionsTest {
    @Test
    fun testListGatherProducts() {
        var list: List<Any>? = null
        @Suppress("KotlinConstantConditions")
        assertEquals(emptySet<Csaf.Product>(), list.gatherProducts())

        list =
            listOf<Any>(
                Csaf.Product(product_id = "my_product", name = "my_product"),
                Csaf.Relationship(
                    category = Category4.installed_on,
                    full_product_name =
                        Csaf.Product(product_id = "my_product2", name = "my_product2"),
                    product_reference = "my_product",
                    relates_to_product_reference = "my_product2",
                ),
                Csaf.Branche(
                    name = "my_branch",
                    category = Category3.product_family,
                    product = Csaf.Product(product_id = "my_product3", name = "my_product3"),
                ),
                Any(),
            )
        val products = list.gatherProducts()
        assertEquals(3, products.size)
        assertEquals(
            setOf("my_product", "my_product2", "my_product3"),
            products.map { it.product_id }.toSet()
        )
    }

    @Test
    fun testProductTreeGatherProducts() {
        var tree: Csaf.ProductTree? = null
        @Suppress("KotlinConstantConditions")
        assertEquals(emptySet<Csaf.Product>(), tree.gatherProducts())

        tree =
            Csaf.ProductTree(
                full_product_names =
                    listOf(Csaf.Product(product_id = "my_product", name = "my_product")),
                relationships =
                    listOf(
                        Csaf.Relationship(
                            category = Category4.installed_on,
                            full_product_name =
                                Csaf.Product(product_id = "my_product2", name = "my_product2"),
                            product_reference = "my_product",
                            relates_to_product_reference = "my_product2",
                        )
                    ),
                branches =
                    listOf(
                        Csaf.Branche(
                            name = "my_branch",
                            category = Category3.product_family,
                            product =
                                Csaf.Product(product_id = "my_product3", name = "my_product3"),
                        )
                    ),
            )

        val products = tree.gatherProducts()
        assertEquals(3, products.size)
        assertEquals(
            setOf("my_product", "my_product2", "my_product3"),
            products.map { it.product_id }.toSet()
        )
    }
}
