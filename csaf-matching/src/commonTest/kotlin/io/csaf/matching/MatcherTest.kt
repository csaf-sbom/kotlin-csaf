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

import io.csaf.matching.properties.ProductNamePropertyProvider
import kotlin.test.*
import protobom.protobom.Document
import protobom.protobom.Node
import protobom.protobom.NodeList
import protobom.protobom.Person
import protobom.protobom.SoftwareIdentifierType

class MatcherTest {

    @Test
    fun `test matchProperty`() {
        val vulnerable = linux40
        val node = Node(name = "Linux Kernel", version = "4.0")
        val match: MatchingConfidence = matchProperty(ProductNamePropertyProvider, vulnerable, node)
        assertIs<DefiniteMatch>(match)
    }

    @Test
    fun `test matchProperties with matching product and version but missing vendor`() {
        val vulnerable = linux40
        // We intentionally do not set the vendor here
        val node = Node(name = "Linux Kernel", version = "4.0")
        val match = matchProperties(vulnerable, node)
        assertIs<MatchWithoutVendor>(match)
    }

    @Test
    fun `test matchProperties with different values`() {
        val expectedMatches =
            mapOf(
                Pair(
                    linux40,
                    Node(
                        name = "Linux Kernel",
                        version = "4.0",
                        suppliers = listOf(Person(name = "Linux", isOrg = true)),
                    ),
                ) to DefiniteMatch,
                Pair(
                    linux40,
                    Node(
                        name = "Linux Kernel",
                        version = "5.0",
                        suppliers = listOf(Person(name = "Linux", isOrg = true)),
                    ),
                ) to DefinitelyNoMatch,
                Pair(
                    linux40,
                    Node(
                        name = "Linux Kernel Enterprise",
                        version = "4.0",
                        suppliers = listOf(Person(name = "Linux", isOrg = true)),
                    ),
                ) to PartialStringMatch,
                Pair(
                    linux40,
                    Node(
                        name = "Linux Körnel",
                        version = "4.0",
                        suppliers = listOf(Person(name = "Linux", isOrg = true)),
                    ),
                ) to DefinitelyNoMatch,
                Pair(linux40, Node(name = "Linux Kernel", version = "4.0")) to MatchWithoutVendor,
                Pair(
                    linux40,
                    Node(
                        name = "Linux Kernel",
                        version = "4.0",
                        identifiers =
                            mapOf(SoftwareIdentifierType.CPE22.value to "cpe:/a:vendor:linux:4.0"),
                    ),
                ) to DefinitelyNoMatch,
                Pair(
                    linux40,
                    Node(
                        name = "Linux Kernel",
                        version = "4.0",
                        identifiers =
                            mapOf(
                                SoftwareIdentifierType.CPE22.value to
                                    "cpe:/o:linux:linux_kernel:4.0"
                            ),
                    ),
                ) to DefiniteMatch,
                Pair(
                    linuxGTE40,
                    Node(
                        name = "Linux Kernel",
                        version = "4.0",
                        suppliers = listOf(Person(name = "Linux", isOrg = true)),
                    ),
                ) to DefiniteMatch,
                Pair(
                    linuxGTE40,
                    Node(
                        name = "Linux Kernel",
                        version = "3.0",
                        suppliers = listOf(Person(name = "Linux", isOrg = true)),
                    ),
                ) to DefinitelyNoMatch,
                Pair(
                    linuxUnspecified,
                    Node(
                        name = "Linux Kernel",
                        version = "4.0",
                        suppliers = listOf(Person(name = "Linux", isOrg = true)),
                    ),
                ) to MatchPackageNoVersion,
            )
        expectedMatches.forEach { pair, expectedMatch ->
            val match = matchProperties(vulnerable = pair.first, node = pair.second)
            assertIs<MatchingConfidence>(match)
            assertEquals(
                expectedMatch,
                match,
                "{${pair.first.product.product_id} vs ${pair.second} expected $expectedMatch but got $match",
            )
        }
    }

    @Test
    fun `test Matcher with null vulnerabilities`() {
        val csafDoc = goodCsaf(vulnerabilities = null)
        val matcher = Matcher(listOf(csafDoc))
        assertNotNull(matcher)
    }

    @Test
    fun `test Matcher initialization with valid threshold`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)
        assertNotNull(matcher)
        assertEquals(0.5f, matcher.threshold)
    }

    @Test
    fun `test Matcher initialization with invalid thresholds`() {
        val csafDoc = goodCsaf()
        assertFailsWith<IllegalArgumentException> { Matcher(listOf(csafDoc), threshold = -0.1f) }
        assertFailsWith<IllegalArgumentException> { Matcher(listOf(csafDoc), threshold = 1.1f) }
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)
        assertFailsWith<IllegalArgumentException> { matcher.match(Document(), threshold = -0.1f) }
        assertFailsWith<IllegalArgumentException> { matcher.match(Document(), threshold = 1.1f) }
    }

    @Test
    fun `test matchDatabase returns nothing for default threshold for empty database`() {
        val matcher =
            Matcher(
                listOf(
                    goodCsaf(
                        productTree = goodProductTree(relationships = null),
                        vulnerabilities = goodVulnerabilities(),
                    )
                )
            )
        val result =
            matcher.matchDatabase(listOf(Document(nodeList = NodeList(nodes = listOf(Node())))))

        assertEquals(0, result.size)
    }

    @Test
    fun `test matchDatabase returns all for threshold 0`() {
        val matcher =
            Matcher(
                listOf(
                    goodCsaf(
                        productTree = goodProductTree(relationships = null),
                        vulnerabilities = goodVulnerabilities(),
                    )
                ),
                threshold = 0.5f,
            )
        val result =
            matcher.matchDatabase(
                listOf(Document(nodeList = NodeList(nodes = listOf(Node())))),
                threshold = 0.0f,
            )

        assertEquals(6, result.size)
    }

    @Test
    fun `test match returns all for threshold 0`() {
        val matcher =
            Matcher(
                listOf(
                    goodCsaf(
                        productTree = goodProductTree(relationships = null),
                        vulnerabilities = goodVulnerabilities(),
                    )
                ),
                threshold = 0.5f,
            )
        val result =
            matcher.match(Document(nodeList = NodeList(nodes = listOf(Node()))), threshold = 0.0f)

        assertEquals(6, result.size)
    }

    @Test
    fun `test match processes valid PURLs correctly`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomWithPurl =
            Document(
                nodeList =
                    NodeList(
                        listOf(
                            Node(
                                identifiers =
                                    mapOf(
                                        SoftwareIdentifierType.PURL.value to
                                            "pkg:rpm/vendor/linux@0.2?arch=src"
                                    )
                            )
                        )
                    )
            )

        val result = matcher.match(sbomWithPurl)
        assertEquals(1, result.size)
        assertEquals(1.0f, result.first().confidence.value)

        val first = result.firstOrNull()
        assertNotNull(first)

        val vuln = first.vulnerabilitiesWithAffectedProduct()
        val firstVuln = vuln.firstOrNull()
        assertEquals("CVE-1234-4000", firstVuln?.cve)

        val notVuln = first.vulnerabilitiesWithNotAffectedProduct()
        assertTrue(notVuln.isEmpty(), "Expected no vulnerabilities with not-affected product")
    }

    @Test
    fun `test match and match process valid CPEs correctly`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomNodeWithCPE =
            Node(
                identifiers =
                    mapOf(SoftwareIdentifierType.CPE22.value to "cpe:/a:vendor:linux:0.1::ab1")
            )
        val sbomWithCPE = Document(nodeList = NodeList(listOf(sbomNodeWithCPE)))

        val resultNode = matcher.matchComponent(sbomNodeWithCPE)
        assertEquals(1, resultNode.size)
        assertEquals(1.0f, resultNode.first().confidence.value)

        val resultAll = matcher.match(sbomWithCPE)
        assertEquals(1, resultAll.size)
        assertEquals(1.0f, resultAll.first().confidence.value)
    }

    @Test
    fun `test match does not add unknown identifiers`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomWithUnknownId =
            Document(nodeList = NodeList(listOf(Node(identifiers = mapOf(999 to "value")))))

        val result = matcher.match(sbomWithUnknownId)
        assertEquals(0, result.size)
    }

    @Test
    fun `test match handles null nodeList`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomWithoutNodeList = Document(nodeList = null)
        val result = matcher.match(sbomWithoutNodeList)

        assertTrue(result.isEmpty())
    }

    @Test
    fun `test match handles null identifiers inside nodes`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomWithNullIdentifiers =
            Document(nodeList = NodeList(listOf(Node(identifiers = emptyMap()))))
        val result = matcher.match(sbomWithNullIdentifiers)

        assertTrue(result.isEmpty())
    }

    @Test
    fun `test match handles missing matching PURLs in sbom`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomWithDifferentPurl =
            Document(
                nodeList =
                    NodeList(
                        listOf(
                            Node(
                                identifiers =
                                    mapOf(
                                        SoftwareIdentifierType.PURL.value to
                                            "pkg:rpm/vendor/linux@1.0.0?arch=src"
                                    )
                            )
                        )
                    )
            )

        val result = matcher.match(sbomWithDifferentPurl)

        assertTrue(result.isEmpty())
    }

    @Test
    fun `test match handles missing matching CPEs in sbom`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomWithDifferentCpe =
            Document(
                nodeList =
                    NodeList(
                        listOf(
                            Node(
                                identifiers =
                                    mapOf(
                                        SoftwareIdentifierType.CPE23.value to
                                            "cpe:2.3:a:vendor:no-match:-:*:*:*:*:*:*:*"
                                    )
                            )
                        )
                    )
            )

        val result = matcher.match(sbomWithDifferentCpe)

        assertTrue(result.isEmpty())
    }
}
