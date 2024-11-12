/*
 * Copyright (c) 2024, The Authors. All rights reserved.
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
package io.github.csaf.sbom.retrieval

import io.github.csaf.sbom.validation.ValidationException
import kotlin.test.*
import kotlinx.coroutines.channels.toList
import kotlinx.coroutines.test.runTest

class RetrievedProviderTest {
    init {
        CsafLoader.defaultLoaderFactory = { CsafLoader(mockEngine()) }
    }

    @Test fun testRetrievedProviderFrom() = runTest { providerTest("example.com") }

    @Test
    fun testRetrievedProviderFromSecurityTxt() = runTest {
        providerTest("provider-with-securitytxt.com")
    }

    @Test
    fun testRetrievedProviderFromDNSPath() = runTest { providerTest("publisher-with-dns.com") }

    @Test
    fun testRetrievedProviderBrokenDomain() {
        val exception =
            assertFailsWith<Exception> {
                runTest { RetrievedProvider.from("broken-domain.com").getOrThrow() }
            }
        assertEquals(
            "Could not retrieve https://csaf.data.security.broken-domain.com: Not Found",
            exception.message
        )
    }

    @Test
    fun testRetrievedProviderEmptyIndex() = runTest {
        val provider = RetrievedProvider.from("no-distributions.com").getOrThrow()
        val expectedDocumentCount = provider.countExpectedDocuments()
        assertEquals(0, expectedDocumentCount)
        val documentResults = provider.fetchDocuments().toList()
        assertTrue(documentResults.isEmpty())
    }

    @Test
    fun testFetchDocumentIndices() = runTest {
        val provider = RetrievedProvider.from("example.com").getOrThrow()
        val documentIndexResults = provider.fetchDocumentIndices().toList()
        assertEquals(
            2,
            documentIndexResults.size,
            "Expected exactly 2 results: One index.txt content and one fetch error"
        )
        assertTrue(documentIndexResults[0].second.isSuccess)
        assertFalse(documentIndexResults[1].second.isSuccess)
    }

    @Test
    fun testFetchRolieFeeds() = runTest {
        val provider = RetrievedProvider.from("example.com").getOrThrow()
        val documentIndexResults = provider.fetchRolieFeeds().toList()
        assertEquals(
            1,
            documentIndexResults.size,
            "Expected exactly 1 results: One index.txt content and one fetch error"
        )
        assertTrue(documentIndexResults[0].second.isSuccess)
    }

    private suspend fun providerTest(domain: String) {
        val provider = RetrievedProvider.from(domain).getOrThrow()
        val expectedDocumentCount = provider.countExpectedDocuments()
        assertEquals(3, expectedDocumentCount, "Expected 3 documents")
        val documentResults = provider.fetchDocuments().toList()
        assertEquals(
            4,
            documentResults.size,
            "Expected exactly 4 results: One document, two document errors, one index error"
        )
        // Check some random property on successful document
        assertEquals(
            "Bundesamt für Sicherheit in der Informationstechnik",
            documentResults[0].getOrThrow().json.document.publisher.name
        )
        // Check document validation error
        val validationException =
            assertIs<ValidationException>(documentResults[1].exceptionOrNull()?.cause)
        assertContentEquals(
            listOf(
                "Filename \"bsi-2022_2-01.json\" does not match conformance, expected \"bsi-2022-0001.json\""
            ),
            validationException.errors
        )
        // Check download error
        val fetchException = assertIs<Exception>(documentResults[2].exceptionOrNull()?.cause)
        assertEquals(
            "Could not retrieve https://$domain/directory/2024/does-not-exist.json: Not Found",
            fetchException.message
        )
        // Check index error
        assertEquals(
            "Failed to fetch index.txt from directory at https://$domain/invalid-directory",
            documentResults[3].exceptionOrNull()?.message
        )
    }
}
