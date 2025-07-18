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
package io.csaf.matching

import io.csaf.schema.JsonUri
import io.csaf.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class MatchTest {

    @Test
    fun testMatchingConfidenceTimes() {
        val expectedMatches =
            mapOf(
                Pair(DefiniteMatch, DefiniteMatch) to DefiniteMatch,
                Pair(DefiniteMatch, MatchPackageNoVersion) to MatchPackageNoVersion,
                Pair(DefiniteMatch, DefinitelyNoMatch) to DefinitelyNoMatch,
                Pair(DefinitelyNoMatch, DefinitelyNoMatch) to DefinitelyNoMatch,
                Pair(MatchPackageNoVersion, DefinitelyNoMatch) to DefinitelyNoMatch,
                Pair(MatchPackageNoVersion, PartialStringMatch) to
                    CombinedMatch(listOf(MatchPackageNoVersion, PartialStringMatch)),
            )
        expectedMatches.forEach { pair, expectedMatch ->
            assertEquals(expectedMatch, pair.first.times(pair.second))
        }
    }

    @Test
    fun testNullGatherVulnerableProducts() {
        val csaf = goodCsaf(productTree = null)
        val vulnerableProducts = csaf.gatherProductsWithBranches()
        assertEquals(emptyList(), vulnerableProducts)
    }

    @Test
    fun testVulnerableProductPurl() {
        var vulnerableProduct =
            ProductWithBranches(
                advisory = goodCsaf(),
                product = Csaf.Product(name = "Product", product_id = "PRODUCT"),
                branches = listOf(),
            )
        assertEquals(null, vulnerableProduct.purl)

        vulnerableProduct =
            ProductWithBranches(
                advisory = goodCsaf(),
                product =
                    Csaf.Product(
                        name = "Product",
                        product_id = "PRODUCT",
                        product_identification_helper =
                            Csaf.ProductIdentificationHelper(purl = null),
                    ),
                branches = listOf(),
            )
        assertEquals(null, vulnerableProduct.purl)

        vulnerableProduct =
            ProductWithBranches(
                advisory = goodCsaf(),
                product =
                    Csaf.Product(
                        name = "Product",
                        product_id = "PRODUCT",
                        product_identification_helper =
                            Csaf.ProductIdentificationHelper(
                                purl = JsonUri("pkg:maven/io.csaf/csaf-matching@1.0.0")
                            ),
                    ),
                branches = listOf(),
            )
        assertIs<Purl>(vulnerableProduct.purl)
    }

    @Test
    fun testVulnerabilitiesWithAffectedProductEmpty() {
        val empty = goodCsaf(vulnerabilities = null)
        val match =
            Match(
                document = empty,
                product =
                    Csaf.Product(
                        name = "Linux 0.1",
                        product_id = "linux-0.1",
                        product_identification_helper =
                            Csaf.ProductIdentificationHelper(cpe = "cpe:/a:vendor:linux:0.1::ab1"),
                    ),
                matchedComponent = SBOMComponent("cpe:/a:vendor:linux:0.1::ab1"),
                confidence = DefiniteMatch,
            )
        assertEquals(emptyList(), match.vulnerabilitiesWithAffectedProduct())
    }

    @Test
    fun testVulnerabilitiesWithNotAffectedProductEmpty() {
        val empty = goodCsaf(vulnerabilities = null)
        val match =
            Match(
                document = empty,
                product =
                    Csaf.Product(
                        name = "Linux 0.1",
                        product_id = "linux-0.1",
                        product_identification_helper =
                            Csaf.ProductIdentificationHelper(cpe = "cpe:/a:vendor:linux:0.1::ab1"),
                    ),
                matchedComponent = SBOMComponent("cpe:/a:vendor:linux:0.1::ab1"),
                confidence = DefiniteMatch,
            )
        assertEquals(emptyList(), match.vulnerabilitiesWithNotAffectedProduct())
    }
}
