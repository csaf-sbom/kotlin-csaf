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
import kotlin.test.Test
import kotlin.test.assertTrue
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

class CPEMatchingTaskTest {
    @Test
    fun testMatch() {
        val affectedCpe = parseCpe("cpe:/a:example:example:1.0")
        val sbomCpe = "cpe:/a:example:example:1.0"

        val matchValue =
            CPEMatchingTask(affectedCpe)
                .match(Node(identifiers = mapOf(SoftwareIdentifierType.CPE22.value to sbomCpe)))
        assertTrue(matchValue is DefiniteMatch)
    }
}
