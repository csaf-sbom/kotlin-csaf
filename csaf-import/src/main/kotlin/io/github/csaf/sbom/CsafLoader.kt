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
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*

/**
 * A helper class with async functions to retrieve certain kinds of CSAF-related data.
 *
 * @param engine An instance of HttpClientEngine for HTTP(S) data retrieval via Ktor. Defaults to
 *   the JVM-native HTTP client.
 */
class CsafLoader(engine: HttpClientEngine = Java.create()) {
    private val httpClient = HttpClient(engine) { install(ContentNegotiation) { json() } }

    /**
     * Fetch and parse an aggregator JSON document from a given URL.
     *
     * @param url The URL where the aggregator document is found.
     * @return An instance of `Aggregator`, wrapped in a `Result` monad, if successful. A failed
     *   `Result` wrapping the thrown `Throwable` in case of an error.
     */
    suspend fun fetchAggregator(url: String): Result<Aggregator> =
        Result.of { httpClient.get(url).body() }

    /**
     * Fetch and parse a provider JSON document from a given URL.
     *
     * @param url The URL where the provider document is found.
     * @return An instance of `Provider`, wrapped in a `Result` monad, if successful. A failed
     *   `Result` wrapping the thrown `Throwable` in case of an error.
     */
    suspend fun fetchProvider(url: String): Result<Provider> =
        Result.of { httpClient.get(url).body() }
}
