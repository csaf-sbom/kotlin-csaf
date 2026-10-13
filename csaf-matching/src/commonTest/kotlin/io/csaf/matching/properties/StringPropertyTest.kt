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
package io.csaf.matching.properties

import io.csaf.matching.*
import kotlin.test.Test
import kotlin.test.assertEquals

/** This test class tests the confidence matching of [StringProperty]. */
class StringPropertyTest {
    @Test
    fun testConfidenceMatching() {
        val expectedMatches =
            mapOf(
                // Exact match
                Pair(
                    "Linux Kernel".toProperty(PropertySource.OTHER),
                    "Linux Kernel".toProperty(PropertySource.OTHER),
                ) to DefiniteMatch,
                // Case-insensitive match
                Pair(
                    "Linux Kernel".toProperty(PropertySource.OTHER),
                    "LInux Kernel".toProperty(PropertySource.OTHER),
                ) to CaseInsensitiveMatch,
                // Case-insensitive match when ignoring dashes
                Pair(
                    "Linux Kernel".toProperty(PropertySource.OTHER),
                    "Linux-Kernel".toProperty(PropertySource.OTHER),
                ) to CaseInsensitiveIgnoreDashMatch,
                // Partial match
                Pair(
                    "Linux Kernel".toProperty(PropertySource.OTHER),
                    "Linux Kernel Enterprise Edition".toProperty(PropertySource.OTHER),
                ) to PartialStringMatch,
                // Case-insensitive match when ignoring dashes and different sources. This can
                // commonly be seen when comparing a CPE with a non-CPE vendor, since CPE vendors
                // are lowercase and have dashes. CSAF branch vendors are human-readable and have
                // spaces.
                Pair(
                    "Linux Kernel".toProperty(PropertySource.OTHER),
                    "linux_kernel".toProperty(PropertySource.CPE),
                ) to
                    CombinedMatch(
                        listOf(
                            CaseInsensitiveIgnoreDashMatch,
                            DifferentSources(listOf(PropertySource.OTHER, PropertySource.CPE)),
                        )
                    ),
            )
        expectedMatches.forEach { pair, expectedMatch ->
            val match = pair.first.confidenceMatching(pair.second)
            assertEquals(
                expectedMatch,
                match,
                "${pair.first} vs ${pair.second} expected $expectedMatch but got $match",
            )
        }
    }
}
