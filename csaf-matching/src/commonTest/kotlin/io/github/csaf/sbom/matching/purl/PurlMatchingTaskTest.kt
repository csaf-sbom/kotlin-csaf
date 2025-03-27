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
package io.github.csaf.sbom.matching.purl

import io.github.csaf.sbom.matching.ProductWithSelector
import io.github.csaf.sbom.schema.JsonUri
import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

class PurlMatchingTaskTest {

    val expectedMatchValues =
        mapOf(
            Pair(
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
            ) to DefiniteMatch,
            Pair(
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-mätching@1.0.0",
            ) to DefinitelyNoMatch,
            Pair("pkg:maven/io.csaf/csaf-matching", "pkg:maven/io.csaf/csaf-matching@1.0.0") to
                MatchPackageNoVersion,
            Pair(
                "pkg:meven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-mätching@1.0.0",
            ) to DefinitelyNoMatch,
            Pair(
                "pkg:maven/iu.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
            ) to DefinitelyNoMatch,
            Pair(
                "pkg:maven/io.csaf/csef-metching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
            ) to DefinitelyNoMatch,
            Pair(
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@0.4.0",
            ) to DefinitelyNoMatch,
            Pair("pkg:maven/io.csaf/csaf-matching@1.0.0", null) to MatcherNotSuitable,
            Pair(null, "pkg:maven/io.csaf/csaf-matching@1.0.0") to MatcherNotSuitable,
        )

    @Test
    fun testMatch() {
        expectedMatchValues.forEach { purlPair, expectedValue ->
            val vulnerablePurl = purlPair.first?.let { Purl(it) }
            val sbomPurl = purlPair.second?.let { Purl(it) }

            val matchValue =
                PurlMatchingTask.match(
                    ProductWithSelector(
                        product =
                            Csaf.Product(
                                product_identification_helper =
                                    vulnerablePurl?.let {
                                        Csaf.ProductIdentificationHelper(
                                            purl = JsonUri(it.canonicalize())
                                        )
                                    },
                                name = "Product",
                                product_id = "CSAF0001",
                            ),
                        additionalSelector = Csaf.Category3.product_name,
                        selectorValue = "Product",
                    ),
                    Node(
                        identifiers =
                            sbomPurl?.let {
                                mapOf(SoftwareIdentifierType.PURL.value to it.canonicalize())
                            } ?: mapOf()
                    ),
                )
            assertEquals(
                expectedValue,
                matchValue,
                "{${vulnerablePurl?.canonicalize()} vs ${sbomPurl?.canonicalize()}} expected $expectedValue but got $matchValue",
            )

            if (expectedValue !is MatcherNotSuitable) {
                assertTrue(expectedValue.value >= 0.0f)
            } else {
                assertEquals(-1.0f, expectedValue.value)
            }
        }
    }
}
