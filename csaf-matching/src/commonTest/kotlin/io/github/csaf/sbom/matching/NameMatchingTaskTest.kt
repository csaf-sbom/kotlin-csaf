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

import io.github.csaf.sbom.matching.purl.DefiniteMatch
import io.github.csaf.sbom.matching.purl.DefinitelyNoMatch
import io.github.csaf.sbom.matching.purl.MatchPackageNoVersion
import io.github.csaf.sbom.matching.purl.MatchingConfidence
import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import protobom.protobom.Node

val productTree =
    Csaf.ProductTree(
        branches =
            listOf(
                Csaf.Branche(
                    name = "Linux Foundation",
                    category = Csaf.Category3.vendor,
                    branches =
                        listOf(
                            Csaf.Branche(
                                category = Csaf.Category3.product_name,
                                name = "Linux Kernel",
                                branches =
                                    listOf(
                                        Csaf.Branche(
                                            product =
                                                Csaf.Product(
                                                    name = "Linux Kernel 4.0",
                                                    product_id = "LINUX_KERNEL_4_0",
                                                ),
                                            category = Csaf.Category3.product_version,
                                            name = "4.0",
                                        )
                                    ),
                            ),
                            Csaf.Branche(
                                product =
                                    Csaf.Product(
                                        name = "Linux Kernel",
                                        product_id = "LINUX_KERNEL_UNSPECIFIED",
                                    ),
                                category = Csaf.Category3.product_name,
                                name = "Linux Kernel",
                            ),
                        ),
                )
            )
    )

class NameMatchingTaskTest {
    @Test
    fun testMatchVersion() {
        val linux40 =
            productTree
                .gatherVulnerableProducts { it.product_id == "LINUX_KERNEL_4_0" }
                .firstOrNull()
        assertNotNull(linux40)

        val linuxUnspecified =
            productTree
                .gatherVulnerableProducts { it.product_id == "LINUX_KERNEL_UNSPECIFIED" }
                .firstOrNull()
        assertNotNull(linuxUnspecified)

        val expectedMatches =
            mapOf(
                Pair(linux40, Node(name = "Linux Kernel", version = "4.0")) to DefiniteMatch,
                Pair(linuxUnspecified, Node(name = "Linux Kernel", version = "4.0")) to
                    MatchPackageNoVersion,
                Pair(linux40, Node(name = "Linux Kernel", version = "5.0")) to DefinitelyNoMatch,
            )

        expectedMatches.forEach { pair, expectedMatch ->
            val match = BranchMatchingTask.match(vulnerable = pair.first, component = pair.second)
            assertIs<MatchingConfidence>(match)
            assertEquals(expectedMatch, match)
        }
    }
}
