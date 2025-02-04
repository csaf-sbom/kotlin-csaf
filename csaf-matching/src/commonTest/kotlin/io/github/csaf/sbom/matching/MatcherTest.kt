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
        val goodCsafDocs =
            listOf(
                goodCsaf(productTree = null),
                goodCsaf(productTree = goodProductTree(fullProductNames = null)),
            )
        val matcher = Matcher(goodCsafDocs, threshold = 0.5f)
        assertNotNull(matcher)
        assertEquals(0.5f, matcher.threshold)
        assertEquals(2, matcher.docs.size)
    }

    @Test
    fun `test Matcher initialization with invalid thresholds`() {
        val csafDoc = goodCsaf()
        assertThrows<IllegalArgumentException> { Matcher(listOf(csafDoc), threshold = -0.1f) }
        assertThrows<IllegalArgumentException> { Matcher(listOf(csafDoc), threshold = 1.1f) }
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)
        assertThrows<IllegalArgumentException> { matcher.match(Document(), threshold = -0.1f) }
        assertThrows<IllegalArgumentException> { matcher.match(Document(), threshold = 1.1f) }
    }

    @Test
    fun `test Matcher initializes empty CSAF list`() {
        val matcher = Matcher(emptyList(), threshold = 0.5f)
        assertTrue(matcher.docs.isEmpty())
        assertTrue(matcher.purlMap.isEmpty())
        assertTrue(matcher.cpeMap.isEmpty())
    }

    @Test
    fun `test Matcher maps correct PURLs`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        assertFalse(matcher.purlMap.isEmpty())
        assertTrue(matcher.purlMap.containsKey("pkg:rpm/vendor/linux@0.2?arch=src"))
    }

    @Test
    fun `test Matcher maps correct CPEs`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        assertFalse(matcher.cpeMap.isEmpty())
        assertEquals(2, matcher.cpeMap.size)
    }

    @Test
    fun `test match returns all documents for threshold 0`() {
        val matcher =
            Matcher(
                listOf(
                    goodCsaf(
                        productTree =
                            goodProductTree(
                                fullProductNames =
                                    goodFullProductNames(productIdentificationHelper = null)
                            )
                    ),
                    goodCsaf(
                        productTree =
                            goodProductTree(
                                fullProductNames =
                                    goodFullProductNames(
                                        productIdentificationHelper =
                                            goodProductIdentificationHelper(cpe = null)
                                    )
                            )
                    ),
                ),
                threshold = 0.5f,
            )
        val result = matcher.match(Document(), threshold = 0.0f)

        assertEquals(2, result.size)
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
        assertEquals(1.0f, result.first().score)
    }

    @Test
    fun `test match processes valid CPEs correctly`() {
        val csafDoc = goodCsaf()
        val matcher = Matcher(listOf(csafDoc), threshold = 0.5f)

        val sbomWithCPE =
            Document(
                nodeList =
                    NodeList(
                        listOf(
                            Node(
                                identifiers =
                                    mapOf(
                                        SoftwareIdentifierType.CPE22.value to
                                            "cpe:/a:vendor:linux:0.1::ab1"
                                    )
                            )
                        )
                    )
            )

        val result = matcher.match(sbomWithCPE)
        assertEquals(1, result.size)
        assertEquals(1.0f, result.first().score)
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
