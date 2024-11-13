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
package io.github.csaf.sbom.retrieval.demo

import io.github.csaf.sbom.retrieval.RetrievedAggregator
import kotlinx.coroutines.runBlocking

fun main(args: Array<String>) {
    runBlocking {
        // Create a new "RetrievedAggregator" from wid.cert-bund.de. This will automatically
        // discover a
        // suitable provider-metadata.json
        RetrievedAggregator.from(
                "https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json"
            )
            .onSuccess { aggregator ->
                println("Loaded aggregator.json @ ${aggregator.json.canonical_url}")
                val providers = aggregator.fetchProviders()
                val publishers = aggregator.fetchPublishers()
                println(
                    "Found ${providers.filter { it.isSuccess }.size} providers and " +
                        "${publishers.filter { it.isSuccess }.size} publishers."
                )
                // Retrieve all documents from all feeds. Note: we currently only support index.txt
                for (result in aggregator.fetchAll()) {
                    result.onSuccess { println("Fetched provider @ ${it.json.canonical_url}") }
                    result.onFailure {
                        println("Could not fetch document: ${it.message}, ${it.cause}")
                    }
                }
            }
            .onFailure {
                println("Could not fetch provider meta from ${args[0]}")
                it.printStackTrace()
            }
    }
}
