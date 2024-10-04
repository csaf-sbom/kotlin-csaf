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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class RetrievedProviderTest {
    @Test
    fun testRetrievedProviderFrom() = runTest {
        var url = "example.com"
        providerTest(url)
    }

    @Test
    fun testRetrievedProviderFromSecurityTxt() = runTest {
        var url = "provider-with-securitytxt.com"
        providerTest(url)
    }

    @Test
    fun testRetrievedProviderFromDNSPath() = runTest {
        var url = "publisher-with-dns.com"
        providerTest(url)
    }

    suspend fun providerTest(url: String) {
        val loader = CsafLoader(mockEngine())
        val provider = RetrievedProvider.from(url, loader).getOrThrow()
        val documentResults = provider.fetchDocuments(loader)
        assertEquals(
            3,
            documentResults.size,
            "Expected exactly 3 results: One document, one document error, one index error"
        )
        // Check some random property on successful document
        assertEquals(
            "Bundesamt für Sicherheit in der Informationstechnik",
            documentResults[0].getOrThrow().json.document.publisher.name
        )
        // Check document error
        assertEquals(
            "Failed to fetch CSAF document from https://$url/directory/2024/does-not-exist.json",
            documentResults[1].exceptionOrNull()?.message
        )
        // Check index error
        assertEquals(
            "Failed to fetch index.txt from directory at https://$url/invalid-directory",
            documentResults[2].exceptionOrNull()?.message
        )
    }
}
