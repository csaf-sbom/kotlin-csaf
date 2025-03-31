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
package io.github.csaf.sbom.matching.properties

import io.github.csaf.sbom.matching.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import protobom.protobom.Node

class PurlPropertyTest {
    @Test
    fun testConfidenceMatching() {
        val expectedMatches =
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
            )
        expectedMatches.forEach { pair, expectedMatch ->
            val match =
                Purl(pair.first).toProperty().confidenceMatching(Purl(pair.second).toProperty())
            assertEquals(
                expectedMatch,
                match,
                "${pair.first} vs ${pair.second} expected $expectedMatch but got $match",
            )
        }
    }

    @Test
    fun testProvider() {
        var provider =
            PurlPropertyProvider.provideProperty(Purl("pkg:maven/io.csaf/csaf-matching@1.0.0"))
        assertNotNull(provider)
        assertEquals("1.0.0", provider.value.version)

        provider = PurlPropertyProvider.provideProperty(Node(version = ""))
        assertNull(provider)
    }
}
