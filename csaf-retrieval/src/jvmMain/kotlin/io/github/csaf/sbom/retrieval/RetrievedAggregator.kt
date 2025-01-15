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

import io.github.csaf.sbom.retrieval.CsafLoader.Companion.lazyLoader
import io.github.csaf.sbom.retrieval.roles.CSAFAggregatorRole
import io.github.csaf.sbom.retrieval.roles.CSAFListerRole
import io.github.csaf.sbom.schema.generated.Aggregator

/**
 * This class represents a wrapper around a [Aggregator] document, that provides functionality for
 * parsing the metadata about an aggregator from a location, including validation according to the
 * specification.
 *
 * This class is not yet complete.
 */
class RetrievedAggregator(val json: Aggregator) : Validatable {

    /**
     * The role of this [RetrievedAggregator] (lister, aggregator), required for checking the
     * validity of the aggregator itself and the Provider instances downloaded by it.
     */
    override val role
        get() =
            when (json.aggregator.category) {
                Aggregator.Category.lister -> CSAFListerRole
                Aggregator.Category.aggregator -> CSAFAggregatorRole
            }

    /**
     * Fetches a list of CSAF providers using the specified loader.
     *
     * @param loader An optional [CsafLoader] instance to use for fetching data. Defaults to
     *   [lazyLoader].
     * @return A list of [Result] objects containing [RetrievedProvider] instances.
     */
    suspend fun fetchProviders(loader: CsafLoader = lazyLoader): List<Result<RetrievedProvider>> {
        return json.csaf_providers.map { providerMeta ->
            val ctx = RetrievalContext()
            loader.fetchProvider(providerMeta.metadata.url.toString(), ctx).mapCatching { p ->
                RetrievedProvider(p).also { it.validate(ctx) }
            }
        }
    }

    /**
     * Fetches a list of CSAF publishers using the specified loader.
     *
     * @param loader An optional [CsafLoader] instance to use for fetching data. Defaults to
     *   [lazyLoader].
     * @return A list of [Result] objects containing [RetrievedProvider] instances.
     */
    suspend fun fetchPublishers(loader: CsafLoader = lazyLoader): List<Result<RetrievedProvider>> {
        return (json.csaf_publishers ?: emptyList()).map { publisherMeta ->
            val ctx = RetrievalContext()
            loader.fetchProvider(publisherMeta.metadata.url.toString(), ctx).mapCatching { p ->
                RetrievedProvider(p).also { it.validate(ctx) }
            }
        }
    }

    /**
     * Fetches all providers and publishers, optionally using the specified loader.
     *
     * @param loader An optional [CsafLoader] instance to use for fetching data. Defaults to
     *   [lazyLoader].
     * @return A list of [Result] objects containing [RetrievedProvider] instances.
     */
    suspend fun fetchAll(loader: CsafLoader = lazyLoader): List<Result<RetrievedProvider>> {
        return fetchProviders(loader) + fetchPublishers(loader)
    }

    companion object {
        /**
         * Retrieves an [Aggregator] from a given [url].
         *
         * @param url The URL where to retrieve the [Aggregator] from.
         * @param loader An instance of [CsafLoader].
         * @return An instance of [RetrievedAggregator], wrapped in a [Result] monad, if successful.
         *   A failed [Result] wrapping the thrown [Throwable] in case of an error.
         */
        suspend fun from(
            url: String,
            loader: CsafLoader = lazyLoader,
        ): Result<RetrievedAggregator> {
            val ctx = RetrievalContext()
            return loader
                .fetchAggregator(url, ctx)
                .mapCatching { a -> RetrievedAggregator(a).also { it.validate(ctx) } }
                .recoverCatching { e ->
                    throw Exception("Failed to load CSAF Aggregator from $url", e)
                }
        }
    }
}
