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
package io.github.csaf.sbom

import io.github.csaf.sbom.generated.Aggregator
import io.github.csaf.sbom.generated.Provider
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json

class CsafLoaderTest {
    private val mockEngine = MockEngine { request ->
        println(request.url.fullPath)
        respond(
            content =
                javaClass.classLoader.getResource(request.url.fullPath.substring(1))!!.readText(),
            status = HttpStatusCode.OK,
            headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
    }
    private val loader = CsafLoader(mockEngine)

    @Test
    fun testFetchAggregator() = runTest {
        val result = loader.fetchAggregator("https://dummy/example-01-aggregator.json")
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

        val json = Json.encodeToString(Aggregator.serializer(), lister)
        assertTrue(json.isNotEmpty())

        val failedResult = loader.fetchAggregator("https://dummy/does-not-exist.json")
        assertFalse(
            failedResult.isSuccess,
            "\"Download\" of https://dummy/does-not-exist.json should produce a failed Result."
        )
    }

    @Test
    fun testFetchProvider() = runTest {
        val result = loader.fetchProvider("https://dummy/example-01-provider-metadata.json")
        assertTrue(
            result.isSuccess,
            "Failed to \"download\" example-01-aggregator.json from resources."
        )

        val provider = result.getOrNull()
        assertNotNull(provider)
        assertEquals(
            "Example Company ProductCERT",
            provider.publisher.name,
            "The publisher name field of the loaded provider does not contain the expected value."
        )

        val json = Json.encodeToString(Provider.serializer(), provider)
        assertTrue(json.isNotEmpty())

        val failedResult = loader.fetchProvider("https://dummy/does-not-exist.json")
        assertFalse(
            failedResult.isSuccess,
            "\"Download\" of https://dummy/does-not-exist.json should produce a failed Result."
        )
    }
}
