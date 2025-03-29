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
import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ProductVersionPropertyTest {
    @Test
    fun testMatchingConfidence() {
        val expectedMatches =
            mapOf(
                // Match with fixed version
                Pair(
                    ProductVersion.Fixed(version = "4.0").toProperty(PropertySource.OTHER),
                    ProductVersion.Fixed(version = "4.0").toProperty(PropertySource.OTHER),
                ) to DefiniteMatch,
                // No match with fixed version
                Pair(
                    ProductVersion.Fixed(version = "4.0").toProperty(PropertySource.OTHER),
                    ProductVersion.Fixed(version = "5.0").toProperty(PropertySource.OTHER),
                ) to DefinitelyNoMatch,
                // Match with range to fixed
                Pair(
                    ProductVersion.Range(range = assertNotNull(parseVers("vers:deb/>=4.0")))
                        .toProperty(PropertySource.OTHER),
                    ProductVersion.Fixed(version = "4.0").toProperty(PropertySource.OTHER),
                ) to DefiniteMatch,
                // Match with fixed to range
                Pair(
                    ProductVersion.Fixed(version = "4.0").toProperty(PropertySource.OTHER),
                    ProductVersion.Range(range = assertNotNull(parseVers("vers:deb/>=4.0")))
                        .toProperty(PropertySource.OTHER),
                ) to DefiniteMatch,
                // Match range to range
                Pair(
                    ProductVersion.Range(range = assertNotNull(parseVers("vers:deb/>=3.0")))
                        .toProperty(PropertySource.OTHER),
                    ProductVersion.Range(range = assertNotNull(parseVers("vers:deb/>=4.0")))
                        .toProperty(PropertySource.OTHER),
                ) to DefiniteMatch,
                // No match with range
                Pair(
                    ProductVersion.Range(range = assertNotNull(parseVers("vers:deb/>=4.0")))
                        .toProperty(PropertySource.OTHER),
                    ProductVersion.Fixed(version = "3.0").toProperty(PropertySource.OTHER),
                ) to DefinitelyNoMatch,
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

    @Test
    fun testProvider() {
        var provider =
            ProductVersionPropertyProvider.provideProperty(
                VulnerableProduct(
                    product = Csaf.Product(product_id = "PID", name = "Product"),
                    branches =
                        listOf(
                            Csaf.Branche(
                                category = Csaf.Category3.product_version_range,
                                name = "not-a-vers",
                            )
                        ),
                )
            )
        assertNull(provider)
    }
}
