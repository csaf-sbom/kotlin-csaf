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

import kotlin.test.Test
import kotlin.test.assertEquals
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

class PurlMatchingTaskTest {

    val expectedMatchValues =
        mapOf(
            Pair(
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
            ) to DEFINITE_MATCH,
            Pair(
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-mätching@1.0.0",
            ) to DEFINITELY_NO_MATCH,
            Pair("pkg:maven/io.csaf/csaf-matching", "pkg:maven/io.csaf/csaf-matching@1.0.0") to
                MATCH_PACKAGE_NO_VERSION,
            Pair(
                "pkg:meven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-mätching@1.0.0",
            ) to DEFINITELY_NO_MATCH,
            Pair(
                "pkg:maven/iu.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
            ) to DEFINITELY_NO_MATCH,
            Pair(
                "pkg:maven/io.csaf/csef-metching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
            ) to DEFINITELY_NO_MATCH,
            Pair(
                "pkg:maven/io.csaf/csaf-matching@1.0.0",
                "pkg:maven/io.csaf/csaf-matching@0.4.0",
            ) to DEFINITELY_NO_MATCH,
        )

    @Test
    fun testMatch() {
        expectedMatchValues.forEach { purlPair, expectedValue ->
            val affectedPurl = Purl(purlPair.first)
            val sbomPurl = Purl(purlPair.second)

            val matchValue =
                PurlMatchingTask(affectedPurl)
                    .match(
                        Node(
                            identifiers =
                                mapOf(SoftwareIdentifierType.PURL.value to sbomPurl.canonicalize())
                        )
                    )
            assertEquals(
                expectedValue,
                matchValue,
                "{${affectedPurl.canonicalize()} vs ${sbomPurl.canonicalize()}} expected $expectedValue but got $matchValue",
            )
        }
    }
}
