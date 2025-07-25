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
package io.csaf.retrieval

import io.ktor.http.*
import kotlin.test.*
import kotlinx.coroutines.test.runTest

class CsafLoaderTest {
    private val loader = CsafLoader(mockEngine())

    @Test
    fun testDefaultConstructor() {
        assertNotNull(CsafLoader())
    }

    @Test
    fun testActualJavaHttpClientEngine() {
        assertNotNull(defaultHttpClientEngine())
    }

    @Test
    fun testInitializeDefaultHttpClient() {
        assertNotNull(defaultHttpClient())
    }

    @Test
    fun testSupplyEngineToDefaultHttpClient() {
        assertNotNull(defaultHttpClient(mockEngine()))
    }

    @Test
    fun testSupplyEngineToCsafLoader() {
        assertNotNull(CsafLoader(mockEngine()))
    }

    @Test
    fun testSupplyClientToCsafLoader() {
        assertNotNull(CsafLoader(null, defaultHttpClient(mockEngine())))
    }

    @Test
    fun testFetchAggregator() = runTest {
        val result = loader.fetchAggregator("https://example.com/example-01-aggregator.json")
        assertTrue(
            result.isSuccess,
            "Failed to \"download\" example-01-aggregator.json from resources.",
        )

        val lister = result.getOrNull()
        assertNotNull(lister)
        assertEquals(
            "Example CSAF Lister",
            lister.aggregator.name,
            "The name field of the loaded aggregator does not contain the expected value.",
        )

        val failedResult = loader.fetchAggregator("https://example.com/does-not-exist.json")
        assertFalse(
            failedResult.isSuccess,
            "\"Download\" of https://example.com/does-not-exist.json should produce a failed Result.",
        )
    }

    @Test
    fun testFetchProvider() = runTest {
        val lines = "line with CRLF\r\n".lines()
        println(lines)

        val result = loader.fetchProvider("https://example.com/example-01-provider-metadata.json")
        assertTrue(
            result.isSuccess,
            "Failed to \"download\" example-01-aggregator.json from resources.",
        )

        val provider = result.getOrNull()
        assertNotNull(provider)
        assertEquals(
            "Example Company ProductCERT",
            provider.publisher.name,
            "The publisher name field of the loaded provider does not contain the expected value.",
        )

        val failedResult = loader.fetchProvider("https://example.com/does-not-exist.json")
        assertFalse(
            failedResult.isSuccess,
            "\"Download\" of https://example.com/does-not-exist.json should produce a failed Result.",
        )
    }

    @Test
    fun testFetchSecurityTxtCsafUrls() = runTest {
        // Test .well-known resolution (preferred).
        val result = loader.fetchSecurityTxtCsafUrls("provider-with-securitytxt.com")
        assertContentEquals(
            listOf(
                "https://provider-with-securitytxt.com/broken-url/provider-metadata.json",
                "https://provider-with-securitytxt.com/directory/provider-metadata.json",
            ),
            result.getOrThrow(),
        )

        // Test fallback location.
        val legacyResult = loader.fetchSecurityTxtCsafUrls("example.com")
        assertContentEquals(
            listOf("https://example.com/.well-known/csaf/provider-metadata.json"),
            legacyResult.getOrThrow(),
        )
    }

    @Test
    fun testFetchInvalidUrl() = runTest {
        val result =
            loader.fetchText("does-not-exist.com/not-available.txt") {
                assertSame(HttpStatusCode.NotFound, it.status)
            }
        assertFalse { result.isSuccess }
    }

    @Test
    fun testFetchROLIEFeed() = runTest {
        val result =
            loader.fetchROLIEFeed("does-not-really-exist.json") {
                assertSame(HttpStatusCode.NotFound, it.status)
            }
        assertFalse { result.isSuccess }
    }

    @Test
    fun testRetriesOnTooManyRequests() = runTest {
        val loader = CsafLoader(tooManyRequestsEngineFactory())
        val result =
            loader.fetchText("does-not-exist.com/too-many-requests.txt") {
                assertSame(HttpStatusCode.OK, it.status)
            }

        assertTrue { result.isSuccess }

        val content = result.getOrThrow()
        assertEquals("Success on attempt 2", content)
    }

    @Test
    fun testRestriesAreLimited() = runTest {
        val loader = CsafLoader(tooManyRequestsEngineFactory(4))
        val result =
            loader.fetchText("does-not-exist.com/too-many-requests.txt") {
                assertSame(HttpStatusCode.TooManyRequests, it.status)
            }
        assertFalse { result.isSuccess }
    }
}
