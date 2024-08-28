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
import io.kjson.ktor.kjson
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*

class CsafLoader(engine: HttpClientEngine = Java.create()) {
    private val httpClient = HttpClient(engine) { install(ContentNegotiation) { kjson() } }

    suspend fun fetchAggregator(url: String): Result<Aggregator> =
        Result.of { httpClient.get(url).body() }

    suspend fun fetchProvider(url: String): Result<Provider> =
        Result.of { httpClient.get(url).body() }
}
