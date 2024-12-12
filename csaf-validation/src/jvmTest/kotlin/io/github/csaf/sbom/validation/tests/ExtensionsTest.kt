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

import io.github.csaf.sbom.schema.JsonUri
import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals

class ExtensionsTest {
    @Test
    fun testGatherProducts() {
        assertEquals(emptyList(), goodCsaf(productTree = null).gatherProductDefinitions())
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        branches =
                                            listOf(
                                                Csaf.Branche(
                                                    category = Csaf.Category3.product_name,
                                                    name = "test",
                                                )
                                            ),
                                        category = Csaf.Category3.host_name,
                                        name = "test",
                                    )
                                )
                        )
                )
                .gatherProductDefinitions()
        )
    }

    @Suppress("USELESS_CAST")
    @Test
    fun testGatherProductReferences() {
        assertEquals(
            listOf(
                "test-product-name",
                "linux-all",
                "linux-product",
                "test-product-name",
                "linux-all",
                "linux-0.1",
                "linux-0.5",
                "linux-0.5",
                "linux-0.1",
                "linux-0.3",
                "linux-0.2",
                "linux-0.5",
                "linux-0.4",
                "linux-0.1",
                "test-product-name",
                "test-product-name",
            ),
            goodCsaf().gatherProductReferences()
        )
        assertEquals(
            listOf(
                "linux-0.1",
                "linux-0.5",
                "linux-0.5",
                "linux-0.1",
                "linux-0.3",
                "linux-0.2",
                "linux-0.5",
                "linux-0.4",
                "linux-0.1",
                "test-product-name",
                "test-product-name"
            ),
            goodCsaf(productTree = null).gatherProductReferences()
        )
        assertEquals(
            listOf(),
            goodCsaf(
                    productTree = null,
                    vulnerabilities = listOf(Csaf.Vulnerability(product_status = null))
                )
                .gatherProductReferences()
        )
        assertEquals(
            listOf(),
            goodCsaf(
                    productTree = null,
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                product_status = null,
                                remediations =
                                    listOf(
                                        Csaf.Remediation(
                                            product_ids = null,
                                            category = Csaf.Category5.no_fix_planned,
                                            details = "deal with it"
                                        )
                                    ),
                                threats =
                                    listOf(
                                        Csaf.Threat(
                                            product_ids = null,
                                            category = Csaf.Category7.exploit_status,
                                            details = "will be exploited"
                                        )
                                    )
                            )
                        )
                )
                .gatherProductReferences()
        )
    }

    @Test
    fun testGatherProductURLs() {
        assertEquals(emptyList(), goodCsaf(productTree = null).gatherProductURLs())
        assertEquals(
            emptyList(),
            goodCsaf(productTree = Csaf.ProductTree(full_product_names = null)).gatherProductURLs()
        )
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            full_product_names =
                                listOf(
                                    Csaf.Product(
                                        name = "My product",
                                        product_id = "product1",
                                        product_identification_helper = null
                                    )
                                ),
                            relationships =
                                listOf(
                                    Csaf.Relationship(
                                        full_product_name =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1_on_the_rocks",
                                                product_identification_helper = null
                                            ),
                                        category = Csaf.Category4.installed_on,
                                        product_reference = "product1",
                                        relates_to_product_reference = "rocks"
                                    )
                                )
                        )
                )
                .gatherProductURLs()
        )
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        category = Csaf.Category3.product_name,
                                        name = "My product",
                                        product =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1",
                                                product_identification_helper =
                                                    Csaf.ProductIdentificationHelper(purl = null)
                                            )
                                    ),
                                )
                        )
                )
                .gatherProductURLs()
        )
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        category = Csaf.Category3.product_name,
                                        name = "My product",
                                        product = null
                                    ),
                                )
                        )
                )
                .gatherProductURLs()
        )
        assertEquals(
            listOf("pkg:github/product/base@1.0.0"),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        category = Csaf.Category3.product_name,
                                        name = "My product",
                                        product =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1",
                                                product_identification_helper =
                                                    Csaf.ProductIdentificationHelper(
                                                        purl =
                                                            JsonUri("pkg:github/product/base@1.0.0")
                                                    )
                                            )
                                    ),
                                )
                        )
                )
                .gatherProductURLs()
        )
        assertEquals(
            listOf("pkg:github/product/rocks@1.0.0"),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            relationships =
                                listOf(
                                    Csaf.Relationship(
                                        full_product_name =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1_on_the_rocks",
                                                product_identification_helper =
                                                    Csaf.ProductIdentificationHelper(
                                                        purl =
                                                            JsonUri(
                                                                "pkg:github/product/rocks@1.0.0"
                                                            )
                                                    )
                                            ),
                                        category = Csaf.Category4.installed_on,
                                        product_reference = "product1",
                                        relates_to_product_reference = "rocks"
                                    )
                                )
                        )
                )
                .gatherProductURLs()
        )
    }

    @Test
    fun testGatherFileHashLists() {
        assertEquals(emptyList(), goodCsaf(productTree = null).gatherFileHashLists())
        assertEquals(
            emptyList(),
            goodCsaf(productTree = Csaf.ProductTree(full_product_names = null))
                .gatherFileHashLists()
        )
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            full_product_names =
                                listOf(
                                    Csaf.Product(
                                        name = "My product",
                                        product_id = "product1",
                                        product_identification_helper = null
                                    )
                                ),
                            relationships =
                                listOf(
                                    Csaf.Relationship(
                                        full_product_name =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1_on_the_rocks",
                                                product_identification_helper = null
                                            ),
                                        category = Csaf.Category4.installed_on,
                                        product_reference = "product1",
                                        relates_to_product_reference = "rocks"
                                    )
                                )
                        )
                )
                .gatherFileHashLists()
        )
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        category = Csaf.Category3.product_name,
                                        name = "My product",
                                        product =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1",
                                                product_identification_helper =
                                                    Csaf.ProductIdentificationHelper(hashes = null)
                                            )
                                    ),
                                )
                        )
                )
                .gatherFileHashLists()
        )
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        category = Csaf.Category3.product_name,
                                        name = "My product",
                                        product = null
                                    ),
                                )
                        )
                )
                .gatherFileHashLists()
        )
        assertEquals(
            emptyList(),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            full_product_names =
                                listOf(
                                    Csaf.Product(
                                        name = "My product",
                                        product_id = "product1",
                                        product_identification_helper =
                                            Csaf.ProductIdentificationHelper(hashes = null)
                                    )
                                ),
                        )
                )
                .gatherFileHashLists()
        )
        assertEquals(
            listOf(goodFileHashes()),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            full_product_names =
                                listOf(
                                    Csaf.Product(
                                        name = "My product",
                                        product_id = "product1",
                                        product_identification_helper =
                                            Csaf.ProductIdentificationHelper(
                                                hashes =
                                                    listOf(
                                                        Csaf.Hashe(
                                                            file_hashes = goodFileHashes(),
                                                            filename = "test.file"
                                                        )
                                                    )
                                            )
                                    )
                                ),
                        )
                )
                .gatherFileHashLists()
        )
        assertEquals(
            listOf(goodFileHashes()),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        category = Csaf.Category3.product_name,
                                        name = "My product",
                                        product =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1",
                                                product_identification_helper =
                                                    Csaf.ProductIdentificationHelper(
                                                        hashes =
                                                            listOf(
                                                                Csaf.Hashe(
                                                                    file_hashes = goodFileHashes(),
                                                                    filename = "test.file"
                                                                )
                                                            )
                                                    )
                                            )
                                    ),
                                )
                        )
                )
                .gatherFileHashLists()
        )
        assertEquals(
            listOf(goodFileHashes()),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            relationships =
                                listOf(
                                    Csaf.Relationship(
                                        full_product_name =
                                            Csaf.Product(
                                                name = "My product",
                                                product_id = "product1_on_the_rocks",
                                                product_identification_helper =
                                                    Csaf.ProductIdentificationHelper(
                                                        hashes =
                                                            listOf(
                                                                Csaf.Hashe(
                                                                    file_hashes = goodFileHashes(),
                                                                    filename = "test.file"
                                                                )
                                                            )
                                                    )
                                            ),
                                        category = Csaf.Category4.installed_on,
                                        product_reference = "product1",
                                        relates_to_product_reference = "rocks"
                                    )
                                )
                        )
                )
                .gatherFileHashLists()
        )
    }

    @Test
    fun testGatherProductGroups() {
        assertEquals(emptyList(), goodCsaf(productTree = null).gatherProductGroups())
    }

    @Test
    fun testGatherProductGroupReferences() {
        assertEquals(emptySet(), goodCsaf(vulnerabilities = null).gatherProductGroupReferences())
        assertEquals(
            emptySet(),
            goodCsaf(
                    vulnerabilities =
                        listOf(Csaf.Vulnerability(remediations = null, threats = null))
                )
                .gatherProductGroupReferences()
        )
        assertEquals(
            emptySet(),
            goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                remediations =
                                    listOf(
                                        Csaf.Remediation(
                                            category = Csaf.Category5.no_fix_planned,
                                            details = "deal with it"
                                        )
                                    ),
                                threats =
                                    listOf(
                                        Csaf.Threat(
                                            category = Csaf.Category7.exploit_status,
                                            details = "will be exploited"
                                        )
                                    )
                            )
                        )
                )
                .gatherProductGroupReferences()
        )
    }

    @Test
    fun testGatherProductIdsPerGroup() {
        assertEquals(mapOf(), goodCsaf(productTree = null).gatherProductIdsPerGroup())
        assertEquals(
            mapOf(),
            goodCsaf(productTree = Csaf.ProductTree(product_groups = null))
                .gatherProductIdsPerGroup()
        )
        assertEquals(
            mapOf("group1" to setOf("product1", "product2")),
            goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            product_groups =
                                listOf(
                                    Csaf.ProductGroup(
                                        group_id = "group1",
                                        product_ids = setOf("product1", "product2")
                                    )
                                )
                        )
                )
                .gatherProductIdsPerGroup()
        )
    }

    @Test
    fun testResolveProductIDs() {
        assertEquals(null, null.resolveProductIDs(mapOf()))
        assertEquals(
            listOf("product1"),
            setOf("group1").resolveProductIDs(mapOf("group1" to setOf("product1")))
        )
        assertEquals(
            listOf(),
            setOf("group2").resolveProductIDs(mapOf("group1" to setOf("product1")))
        )
    }

    @Test
    fun testPlus() {
        assertEquals(setOf("a", "b"), setOf("a") + setOf("b"))
        assertEquals(setOf("a"), setOf("a") + null)
        assertEquals(setOf("a"), null + setOf("a"))
        assertEquals(emptySet<String>(), null + null)
    }

    @Test
    fun testMinus() {
        assertEquals(setOf("a"), setOf("a") - setOf("b"))
        assertEquals(setOf("b"), setOf("a", "b") - setOf("a"))
        assertEquals(setOf("a"), setOf("a") - null)
        assertEquals(emptySet<String>(), null - setOf("a"))
        assertEquals(emptySet<String>(), null - null)
    }
}
