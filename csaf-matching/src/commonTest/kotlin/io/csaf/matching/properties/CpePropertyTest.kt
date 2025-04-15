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

import io.csaf.matching.DefiniteMatch
import io.csaf.matching.DefinitelyNoMatch
import io.csaf.matching.parseCpe
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class CpePropertyTest {
    @Test
    fun testConfidenceMatching() {
        val expectedMatches =
            mapOf(
                Pair("cpe:/a:example:example:1.0", "cpe:/a:example:example:1.0") to DefiniteMatch,
                Pair("cpe:/a:example:example:1.0", "cpe:/a:example:example:2.0") to
                    DefinitelyNoMatch,
                Pair("cpe:/a:example:example", "cpe:/a:example:example:1.0") to DefiniteMatch,
                Pair("cpe:/a:exmple:example:1.0", "cpe:/a:example:example:1.0") to
                    DefinitelyNoMatch,
                Pair("cpe:/a:example:xample:1.0", "cpe:/a:example:example:1.0") to
                    DefinitelyNoMatch,
                Pair("cpe:/a:example:example", "cpe:/a:example:xample:1.0") to DefinitelyNoMatch,
                Pair("cpe:/a:example:xample", "cpe:/a:example:xample") to DefiniteMatch,
            )
        expectedMatches.forEach { pair, expectedMatch ->
            val match =
                parseCpe(pair.first)
                    .toProperty()
                    .confidenceMatching(parseCpe(pair.second).toProperty())
            assertEquals(
                expectedMatch,
                match,
                "${pair.first} vs ${pair.second} expected $expectedMatch but got $match",
            )
        }
    }

    @Test
    fun testProvider() {
        val provider = CpePropertyProvider.provideProperty(parseCpe("cpe:/a:example:example:1.0"))
        assertNotNull(provider)
        assertEquals("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", provider.value.toCpe23FS())
    }
}
