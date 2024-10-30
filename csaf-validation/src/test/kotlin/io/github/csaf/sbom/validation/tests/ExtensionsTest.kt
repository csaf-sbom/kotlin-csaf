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
import io.github.csaf.sbom.validation.goodCsaf
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
            setOf(
                "linux-0.1",
                "linux-0.5",
                "linux-0.3",
                "linux-0.2",
                "linux-0.4",
                "linux-all",
                "linux-product",
                "test-product-name",
            ),
            goodCsaf().gatherProductReferences()
        )
        assertEquals(
            setOf(
                "linux-0.1",
                "linux-0.5",
                "linux-0.3",
                "linux-0.2",
                "linux-0.4",
                "test-product-name"
            ),
            goodCsaf(productTree = null).gatherProductReferences()
        )
        assertEquals(
            setOf(),
            goodCsaf(
                    productTree = null,
                    vulnerabilities = listOf(Csaf.Vulnerability(product_status = null))
                )
                .gatherProductReferences()
        )
        assertEquals(
            setOf(),
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
}
