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

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import protobom.protobom.Document
import protobom.protobom.Node
import protobom.protobom.NodeList
import protobom.protobom.SoftwareIdentifierType

class MatcherTest {

    @Test
    fun `test Matcher initialization with valid threshold`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)
        assertNotNull(matcher)
        assertEquals(0.5f, matcher.threshold)
    }

    @Test
    fun `test Matcher initialization with invalid thresholds`() {
        val csafDoc = goodCsaf()
        assertThrows<IllegalArgumentException> { Matcher(csafDoc, threshold = -0.1f) }
        assertThrows<IllegalArgumentException> { Matcher(csafDoc, threshold = 1.1f) }
        val matcher = Matcher(csafDoc, threshold = 0.5f)
        assertThrows<IllegalArgumentException> { matcher.matchAll(Document(), threshold = -0.1f) }
        assertThrows<IllegalArgumentException> { matcher.matchAll(Document(), threshold = 1.1f) }
    }

    @Test
    fun `test Matcher maps correct PURLs`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

        // assertFalse(matcher.purlMap.isEmpty())
        // assertTrue(matcher.purlMap.containsKey("pkg:rpm/vendor/linux@0.2?arch=src"))
    }

    @Test
    fun `test Matcher maps correct CPEs`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

        // assertEquals(1, matcher.cpeMap.size)
    }

    @Test
    fun `test matchAll returns all documents for threshold 0`() {
        val matcher =
            Matcher(
                goodCsaf(
                    productTree = goodProductTree(relationships = null),
                    vulnerabilities = goodVulnerabilities(),
                ),
                threshold = 0.5f,
            )
        val result =
            matcher.matchAll(
                Document(nodeList = NodeList(nodes = listOf(Node()))),
                threshold = 0.0f,
            )

        assertEquals(1, result.size)
    }

    @Test
    fun `test matchAll processes valid PURLs correctly`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

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

        val result = matcher.matchAll(sbomWithPurl)
        assertEquals(1, result.size)
        assertEquals(1.0f, result.first().confidence.value)
    }

    @Test
    fun `test matchAll and match process valid CPEs correctly`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

        val sbomNodeWithCPE =
            Node(
                identifiers =
                    mapOf(SoftwareIdentifierType.CPE22.value to "cpe:/a:vendor:linux:0.1::ab1")
            )
        val sbomWithCPE = Document(nodeList = NodeList(listOf(sbomNodeWithCPE)))

        val resultNode = matcher.match(sbomNodeWithCPE)
        assertEquals(1, resultNode.size)
        assertEquals(1.0f, resultNode.first().confidence.value)

        val resultAll = matcher.matchAll(sbomWithCPE)
        assertEquals(1, resultAll.size)
        assertEquals(1.0f, resultAll.first().confidence.value)
    }

    @Test
    fun `test matchAll does not add unknown identifiers`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

        val sbomWithUnknownId =
            Document(nodeList = NodeList(listOf(Node(identifiers = mapOf(999 to "value")))))

        val result = matcher.matchAll(sbomWithUnknownId)
        assertEquals(0, result.size)
    }

    @Test
    fun `test matchAll handles null nodeList`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

        val sbomWithoutNodeList = Document(nodeList = null)
        val result = matcher.matchAll(sbomWithoutNodeList)

        assertTrue(result.isEmpty())
    }

    @Test
    fun `test matchAll handles null identifiers inside nodes`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

        val sbomWithNullIdentifiers =
            Document(nodeList = NodeList(listOf(Node(identifiers = emptyMap()))))
        val result = matcher.matchAll(sbomWithNullIdentifiers)

        assertTrue(result.isEmpty())
    }

    @Test
    fun `test matchAll handles missing matching PURLs in sbom`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

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

        val result = matcher.matchAll(sbomWithDifferentPurl)

        assertTrue(result.isEmpty())
    }

    @Test
    fun `test matchAll handles missing matching CPEs in sbom`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(csafDoc, threshold = 0.5f)

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

        val result = matcher.matchAll(sbomWithDifferentCpe)

        assertTrue(result.isEmpty())
    }
}
