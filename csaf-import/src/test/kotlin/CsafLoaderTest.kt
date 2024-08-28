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
import io.github.csaf.sbom.CsafLoader
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

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
        assert(result.isSuccess) {
            "Failed to \"download\" example-01-aggregator.json from resources."
        }
        assertEquals(
            "Example CSAF Lister",
            result.getOrThrow().aggregator.name,
            "The name field of the loaded aggregator does not contain the expected value."
        )
    }

    @Test
    fun testFetchProvider() = runTest {
        val result = loader.fetchProvider("https://dummy/example-01-provider-metadata.json")
        assert(result.isSuccess) {
            "Failed to \"download\" example-01-aggregator.json from resources."
        }
        assertEquals(
            "Example Company ProductCERT",
            result.getOrThrow().publisher.name,
            "The publisher name field of the loaded provider does not contain the expected value."
        )
    }
}
