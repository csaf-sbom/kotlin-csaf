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
import io.ktor.client.plugins.ResponseException
import io.ktor.client.statement.request
import io.ktor.http.HttpStatusCode
import kotlin.test.*
import kotlinx.coroutines.channels.toList
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Instant
import org.junit.jupiter.api.assertThrows

class RetrievedProviderTest {
    init {
        CsafLoader.defaultLoaderFactory = { CsafLoader(mockEngine()) }
    }

    @Test fun testRetrievedProviderFrom() = runTest { providerTest("example.com", 4) }

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
                runTest { RetrievedProvider.fromDomain("broken-domain.com").getOrThrow() }
            }
        assertTrue(
            exception.message!!.startsWith(
                "Failed to resolve provider for broken-domain.com via all implemented methods:"
            ),
            "Expected exception message to start with \"Failed to resolve provider for...\"",
        )
        assertEquals(
            4,
            exception.message!!.split('\n').count(),
            "Expected 4 lines in exception message",
        )
    }

    @Test
    fun testRetrievedProviderEmptyIndex() = runTest {
        val provider = RetrievedProvider.fromDomain("no-distributions.com").getOrThrow()
        val expectedDocumentCount = provider.countExpectedDocuments()
        assertEquals(0, expectedDocumentCount)
        val documentResults = provider.fetchDocuments().toList()
        assertTrue(documentResults.isEmpty())
    }

    @Test
    fun testFetchDocumentIndices() = runTest {
        val provider = RetrievedProvider.fromDomain("example.com").getOrThrow()
        val documentIndexResults = provider.fetchDocumentIndices().toList()
        assertEquals(
            2,
            documentIndexResults.size,
            "Expected exactly 2 results: One index.txt content and one fetch error",
        )
        assertTrue(documentIndexResults[0].second.isSuccess)
        assertFalse(documentIndexResults[1].second.isSuccess)
        val expectedContent = getResourceUrl("example.com/directory/index.txt")?.readText()
        assertEquals(
            expectedContent,
            documentIndexResults[0].second.getOrThrow(),
            "Expected index.txt content to match",
        )
    }

    @Test
    fun testFetchDocumentChangesCsv() = runTest {
        val provider = RetrievedProvider.fromDomain("example.com").getOrThrow()
        val documentIndexResults = provider.fetchDocumentIndices(useChangesCsv = true).toList()
        assertEquals(
            2,
            documentIndexResults.size,
            "Expected exactly 2 results: One changes.csv content and one fetch error",
        )
        assertTrue(documentIndexResults[0].second.isSuccess)
        assertFalse(documentIndexResults[1].second.isSuccess)
        val expectedContent = getResourceUrl("example.com/directory/changes.csv")?.readText()
        assertEquals(
            expectedContent,
            documentIndexResults[0].second.getOrThrow(),
            "Expected changes.csv content to match",
        )
    }

    @Test
    fun testFetchRolieFeeds() = runTest {
        val provider = RetrievedProvider.fromDomain("example.com").getOrThrow()
        val rolieFeedsResults = provider.fetchRolieFeeds().toList()
        assertEquals(1, rolieFeedsResults.size, "Expected exactly 1 result: One parsed ROLIE feed")
        assertTrue(rolieFeedsResults[0].second.isSuccess)
    }

    private suspend fun providerTest(domain: String, numResults: Int = 5) {
        val provider = RetrievedProvider.fromDomain(domain).getOrThrow()
        val expectedDocumentCount = provider.countExpectedDocuments()
        assertEquals(3, expectedDocumentCount, "Expected 3 documents")
        val documentResults = provider.fetchDocuments().toList()
        assertEquals(numResults, documentResults.size, "Expected exactly $numResults results")
        // Check some random property on successful document
        assertEquals(
            "Bundesamt für Sicherheit in der Informationstechnik",
            documentResults[0].getOrThrow().json.document.publisher.name,
        )
        // Check document validation error
        val validationException =
            assertIs<ValidationException>(documentResults[1].exceptionOrNull()?.cause)
        assertContentEquals(
            listOf(
                "Filename \"bsi-2022_2-01.json\" does not match conformance, expected \"bsi-2022-0001.json\""
            ),
            validationException.errors,
        )
        // Check download error
        val retrievalException = assertIs<RetrievalException>(documentResults[2].exceptionOrNull())
        assertEquals(
            "https://$domain/directory/2024/does-not-exist.json",
            retrievalException.url,
            "Expected given invalid URL",
        )
        val fetchException = assertIs<ResponseException>(retrievalException.cause)
        assertEquals(HttpStatusCode.NotFound, fetchException.response.status, "Expected 404 status")
        // Check index error
        assertEquals(
            "Failed to fetch index.txt from directory at https://$domain/invalid-directory",
            documentResults[3].exceptionOrNull()?.message,
        )
    }

    @Test
    fun testProviderByUrl() = runTest {
        val providerByDomain = RetrievedProvider.fromDomain("example.com").getOrThrow().toString()
        val providerByUrl =
            RetrievedProvider.fromUrl("https://example.com/.well-known/csaf/provider-metadata.json")
                .getOrThrow()
                .toString()
        assertEquals(
            providerByDomain,
            providerByUrl,
            "Retrieved providers via domain and URL should be equal",
        )
        val invalidProviderUrl = "https://does-not-exist.com/provider-metadata.json"
        val invalidProviderByUrl = RetrievedProvider.fromUrl(invalidProviderUrl)
        val fetchException = assertIs<ResponseException>(invalidProviderByUrl.exceptionOrNull())
        assertEquals(HttpStatusCode.NotFound, fetchException.response.status, "Expected 404 status")
        assertEquals(
            invalidProviderUrl,
            fetchException.response.request.url.toString(),
            "Expected identical URL",
        )
    }

    @Test
    fun testFetchAllDocumentUrls() = runTest {
        val provider = RetrievedProvider.fromDomain("example.com").getOrThrow()
        val resultList = provider.fetchAllDocumentUrls().toList()
        resultList.let { urlResults ->
            assertEquals(4, urlResults.size, "Expected exactly 4 results")
            assertEquals(
                "https://example.com/directory/2022/bsi-2022-0001.json",
                urlResults[0].getOrThrow(),
            )
            assertEquals(
                "https://example.com/directory/2022/bsi-2022_2-01.json",
                urlResults[1].getOrThrow(),
            )
            assertEquals(
                "https://example.com/directory/2024/does-not-exist.json",
                urlResults[2].getOrThrow(),
            )
            assertEquals(
                "Failed to fetch index.txt from directory at https://example.com/invalid-directory",
                (assertThrows<Exception> { urlResults[3].getOrThrow() }).message,
            )
        }
        // Distant past must result in the same behavior as "null", except for some error messages.
        val distantPastResultList =
            provider.fetchAllDocumentUrls(startingFrom = Instant.DISTANT_PAST).toList()
        assertContentEquals(resultList.subList(0, 3), distantPastResultList.subList(0, 3))
        assertEquals(
            "Failed to fetch changes.csv from directory at https://example.com/invalid-directory",
            (assertThrows<Exception> { distantPastResultList[3].getOrThrow() }).message,
        )
        provider
            .fetchAllDocumentUrls(startingFrom = Instant.parse("2022-02-01T00:00:00Z"))
            .toList()
            .let { results ->
                assertEquals(2, results.size, "Expected exactly 4 results")
                assertEquals(
                    "https://example.com/directory/2022/bsi-2022_2-01.json",
                    results[0].getOrThrow(),
                )
                assertEquals(
                    "Failed to fetch changes.csv from directory at https://example.com/invalid-directory",
                    (assertThrows<Exception> { results[1].getOrThrow() }).message,
                )
            }
    }
}
