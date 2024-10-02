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

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@KoverIgnore("Entry point for demo purposes only")
fun main() {
    val json = Json { prettyPrint = true }
    val loader = CsafLoader()
    runBlocking {
        val aggregator =
            loader.fetchAggregator(
                "https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json"
            )
        aggregator
            .onSuccess { ag ->
                ag.csaf_providers
                    .mapAsync { loader.fetchProvider(it.metadata.url.toString()) }
                    .forEach { provider ->
                        provider
                            .onSuccess { println(json.encodeToString(it)) }
                            .onFailure { it.printStackTrace() }
                        println("\n##################################################\n")
                    }
            }
            .onFailure { it.printStackTrace() }
    }
}
