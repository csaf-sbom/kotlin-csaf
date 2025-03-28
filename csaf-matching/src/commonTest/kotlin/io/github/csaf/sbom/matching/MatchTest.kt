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

import kotlin.test.Test
import kotlin.test.assertEquals

class MatchTest {

    @Test
    fun testMatchingConfidencePlus() {
        val expectedMatches =
            mapOf(
                Pair(DefiniteMatch, DefiniteMatch) to DefiniteMatch,
                Pair(DefiniteMatch, MatchPackageNoVersion) to MatchPackageNoVersion,
                Pair(DefiniteMatch, DefinitelyNoMatch) to DefinitelyNoMatch,
                Pair(DefinitelyNoMatch, DefinitelyNoMatch) to DefinitelyNoMatch,
                Pair(MatchPackageNoVersion, DefinitelyNoMatch) to DefinitelyNoMatch,
                Pair(MatchPackageNoVersion, PartialNameMatch) to
                    CombinedMatch(listOf(MatchPackageNoVersion, PartialNameMatch)),
            )
        expectedMatches.forEach { pair, expectedMatch ->
            assertEquals(expectedMatch, pair.first + pair.second)
        }
    }
}
