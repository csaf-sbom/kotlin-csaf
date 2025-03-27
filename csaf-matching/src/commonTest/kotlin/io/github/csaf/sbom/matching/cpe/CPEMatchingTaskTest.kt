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
package io.github.csaf.sbom.matching.cpe

import io.github.csaf.sbom.matching.purl.DefiniteMatch
import io.github.csaf.sbom.matching.purl.DefinitelyNoMatch
import io.github.csaf.sbom.matching.purl.MatcherNotSuitable
import io.github.csaf.sbom.schema.JsonUri
import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

class CPEMatchingTaskTest {

    val expectedMatchValues =
        mapOf(
            Pair("cpe:/a:example:example:1.0", "cpe:/a:example:example:1.0") to DefiniteMatch,
            Pair("cpe:/a:example:example:1.0", "cpe:/a:example:example:2.0") to DefinitelyNoMatch,
            Pair("cpe:/a:example:example", "cpe:/a:example:example:1.0") to DefiniteMatch,
            Pair("cpe:/a:exmple:example:1.0", "cpe:/a:example:example:1.0") to DefinitelyNoMatch,
            Pair("cpe:/a:example:xample:1.0", "cpe:/a:example:example:1.0") to DefinitelyNoMatch,
            Pair("cpe:/a:example:example", "cpe:/a:example:xample:1.0") to DefinitelyNoMatch,
            Pair("cpe:/a:example:xample", "cpe:/a:example:xample") to DefiniteMatch,
            Pair("cpe:/a:example:example", null) to MatcherNotSuitable,
            Pair(null, "cpe:/a:example:example") to MatcherNotSuitable,
        )

    @Test
    fun testMatchCPE22() {
        expectedMatchValues.forEach { purlCpe, expectedValue ->
            val vulnerableCpe = purlCpe.first?.let { parseCpe(it) }
            val sbomCpe = purlCpe.second?.let { parseCpe(it) }

            val matchValue =
                CPEMatchingTask.match(
                    Csaf.Product(
                        product_identification_helper =
                            vulnerableCpe?.let {
                                Csaf.ProductIdentificationHelper(purl = JsonUri(it.toCpe23FS()))
                            },
                        name = "Product",
                        product_id = "CSAF0001",
                    ),
                    Node(
                        identifiers =
                            sbomCpe?.let {
                                mapOf(SoftwareIdentifierType.CPE22.value to it.toCpe23FS())
                            } ?: mapOf()
                    ),
                )
            assertEquals(
                expectedValue,
                matchValue,
                "{${vulnerableCpe} vs ${sbomCpe}} expected $expectedValue but got $matchValue",
            )

            if (expectedValue !is MatcherNotSuitable) {
                assertTrue(expectedValue.value >= 0.0f)
            } else {
                assertEquals(-1.0f, expectedValue.value)
            }
        }
    }

    @Test
    fun testMatchCPE23() {
        expectedMatchValues.forEach { purlCpe, expectedValue ->
            val vulnerableCpe = purlCpe.first?.let { parseCpe(it) }
            val sbomCpe = purlCpe.second?.let { parseCpe(it) }

            val matchValue =
                CPEMatchingTask.match(
                    Csaf.Product(
                        product_identification_helper =
                            vulnerableCpe?.let {
                                Csaf.ProductIdentificationHelper(purl = JsonUri(it.toCpe23FS()))
                            },
                        name = "Product",
                        product_id = "CSAF0001",
                    ),
                    Node(
                        identifiers =
                            sbomCpe?.let {
                                mapOf(SoftwareIdentifierType.CPE23.value to it.toCpe23FS())
                            } ?: mapOf()
                    ),
                )
            assertEquals(
                expectedValue,
                matchValue,
                "{${vulnerableCpe} vs ${sbomCpe}} expected $expectedValue but got $matchValue",
            )

            if (expectedValue !is MatcherNotSuitable) {
                assertTrue(expectedValue.value >= 0.0f)
            } else {
                assertEquals(-1.0f, expectedValue.value)
            }
        }
    }
}
