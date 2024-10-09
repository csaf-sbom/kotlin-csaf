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

import io.github.csaf.sbom.validation.ValidationContext
import io.github.csaf.sbom.validation.ValidationException
import kotlin.test.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertThrows

class CsafLoaderTest {
    private val loader = CsafLoader(mockEngine())

    @Test
    fun testFetchAggregator() = runTest {
        val result = loader.fetchAggregator("https://example.com/example-01-aggregator.json")
        assertTrue(
            result.isSuccess,
            "Failed to \"download\" example-01-aggregator.json from resources."
        )

        val lister = result.getOrNull()
        assertNotNull(lister)
        assertEquals(
            "Example CSAF Lister",
            lister.aggregator.name,
            "The name field of the loaded aggregator does not contain the expected value."
        )

        val failedResult = loader.fetchAggregator("https://example.com/does-not-exist.json")
        assertFalse(
            failedResult.isSuccess,
            "\"Download\" of https://example.com/does-not-exist.json should produce a failed Result."
        )
    }

    @Test
    fun testFetchProvider() = runTest {
        val result = loader.fetchProvider("https://example.com/example-01-provider-metadata.json")
        assertTrue(
            result.isSuccess,
            "Failed to \"download\" example-01-aggregator.json from resources."
        )
        // Fresh [ValidationContext] should always throw.
        assertThrows<ValidationException> {
            RetrievedProvider(result.getOrThrow()).validate(ValidationContext())
        }

        val provider = result.getOrNull()
        assertNotNull(provider)
        assertEquals(
            "Example Company ProductCERT",
            provider.publisher.name,
            "The publisher name field of the loaded provider does not contain the expected value."
        )

        val failedResult = loader.fetchProvider("https://example.com/does-not-exist.json")
        assertFalse(
            failedResult.isSuccess,
            "\"Download\" of https://example.com/does-not-exist.json should produce a failed Result."
        )
    }

    @Test
    fun testFetchSecurityTxtCsafUrls() = runTest {
        // Test .well-known resolution (preferred).
        val result = loader.fetchSecurityTxtCsafUrls("provider-with-securitytxt.com")
        assertContentEquals(
            listOf(
                "https://provider-with-securitytxt.com/broken-url/provider-metadata.json",
                "https://provider-with-securitytxt.com/directory/provider-metadata.json"
            ),
            result.getOrThrow()
        )

        // Test fallback location.
        val legacyResult = loader.fetchSecurityTxtCsafUrls("example.com")
        assertContentEquals(
            listOf("https://example.com/.well-known/csaf/provider-metadata.json"),
            legacyResult.getOrThrow()
        )
    }
}
