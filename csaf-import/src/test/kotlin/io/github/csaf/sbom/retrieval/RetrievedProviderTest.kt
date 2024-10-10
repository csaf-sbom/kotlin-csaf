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
        val documentResults = provider.fetchDocuments()
        assertEquals(0, documentResults.size)
    }

    private suspend fun providerTest(url: String) {
        val provider = RetrievedProvider.from(url).getOrThrow()
        val documentResults = provider.fetchDocuments()
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
            listOf("Filename bsi-2022_2-01.json does not match conformance"),
            validationException.errors
        )
        // Check download error
        val fetchException = assertIs<Exception>(documentResults[2].exceptionOrNull()?.cause)
        assertEquals(
            "Could not retrieve https://$url/directory/2024/does-not-exist.json: Not Found",
            fetchException.message
        )
        // Check index error
        assertEquals(
            "Failed to fetch index.txt from directory at https://$url/invalid-directory",
            documentResults[3].exceptionOrNull()?.message
        )
    }
}
