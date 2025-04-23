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

import io.csaf.retrieval.CsafLoader.Companion.lazyLoader
import io.csaf.retrieval.roles.CSAFAggregatorRole
import io.csaf.retrieval.roles.CSAFListerRole
import io.csaf.schema.generated.Aggregator
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.future.future

/**
 * This class represents a wrapper around a [Aggregator] document, that provides functionality for
 * parsing the metadata about an aggregator from a location, including validation according to the
 * specification.
 *
 * This class is not yet complete.
 */
data class RetrievedAggregator(val json: Aggregator) : Validatable {

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

    /**
     * Fetches a list of CSAF providers asynchronously, allowing Java invocation. Converts the
     * results into [ResultCompat] for Java compatibility.
     *
     * @param loader An optional [CsafLoader] instance to use for fetching data. Defaults to
     *   [lazyLoader].
     * @return A [CompletableFuture] that resolves to a list of [ResultCompat] objects.
     */
    @JvmOverloads
    fun fetchProvidersAsync(
        loader: CsafLoader = lazyLoader
    ): CompletableFuture<List<ResultCompat<RetrievedProvider>>> =
        ioScope.future { fetchProviders(loader).map { ResultCompat(it) } }

    /**
     * Fetches a list of CSAF publishers asynchronously, allowing Java invocation. Converts the
     * results into [ResultCompat] for Java compatibility.
     *
     * @param loader An optional [CsafLoader] instance to use for fetching data. Defaults to
     *   [lazyLoader].
     * @return A [CompletableFuture] that resolves to a list of [ResultCompat] objects.
     */
    @JvmOverloads
    fun fetchPublishersAsync(
        loader: CsafLoader = lazyLoader
    ): CompletableFuture<List<ResultCompat<RetrievedProvider>>> =
        ioScope.future { fetchPublishers(loader).map { ResultCompat(it) } }

    /**
     * Fetches all providers and publishers asynchronously, allowing Java invocation. Converts the
     * results into [ResultCompat] for Java compatibility.
     *
     * @param loader An optional [CsafLoader] instance to use for fetching data. Defaults to
     *   [lazyLoader].
     * @return A [CompletableFuture] that resolves to a list of [ResultCompat] objects.
     */
    @JvmOverloads
    fun fetchAllAsync(
        loader: CsafLoader = lazyLoader
    ): CompletableFuture<List<ResultCompat<RetrievedProvider>>> =
        ioScope.future { fetchAll(loader).map { ResultCompat(it) } }

    companion object {
        private val ioScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

        /**
         * Retrieves a [RetrievedAggregator] asynchronously from the provided URL.
         *
         * @param url The URL to retrieve the aggregator from.
         * @param loader An optional [CsafLoader] instance. Defaults to [lazyLoader].
         * @return A [CompletableFuture] that wraps a [RetrievedAggregator] instance upon success,
         *   or the thrown [Throwable] in case of an error.
         */
        @JvmStatic
        @JvmOverloads
        fun fromUrlAsync(
            url: String,
            loader: CsafLoader = lazyLoader,
        ): CompletableFuture<RetrievedAggregator> {
            return ioScope.future { fromUrl(url, loader).getOrThrow() }
        }

        /**
         * Retrieves a [RetrievedAggregator] asynchronously from the provided domain.
         *
         * @param domain The domain to retrieve the aggregator from.
         * @param loader An optional [CsafLoader] instance. Defaults to [lazyLoader].
         * @return A [CompletableFuture] that wraps a [RetrievedAggregator] instance upon success,
         *   or the thrown [Throwable] in case of an error.
         */
        @JvmStatic
        @JvmOverloads
        fun fromDomainAsync(
            domain: String,
            loader: CsafLoader = lazyLoader,
        ): CompletableFuture<RetrievedAggregator> {
            return ioScope.future { fromDomain(domain, loader).getOrThrow() }
        }

        /**
         * Retrieves a [RetrievedAggregator] from a given URL.
         *
         * @param url The URL to retrieve the [RetrievedAggregator] from.
         * @param loader An optional [CsafLoader] instance. Defaults to [lazyLoader].
         * @return An instance of [RetrievedAggregator], wrapped in a [Result] monad, if successful.
         *   A failed [Result] wrapping the thrown [Throwable] in case of an error.
         */
        suspend fun fromUrl(
            url: String,
            loader: CsafLoader = lazyLoader,
        ): Result<RetrievedAggregator> {
            val ctx = RetrievalContext()
            return loader
                .fetchAggregator(url, ctx)
                .mapCatching { a -> RetrievedAggregator(a).also { it.validate(ctx) } }
                .recoverCatching { e ->
                    throw RetrievalException("Failed to load CSAF Aggregator from $url", e)
                }
        }

        /**
         * Retrieves a [RetrievedAggregator] from a given domain using the well-known URL
         * `/.well-known/csaf-aggregator/aggregator.json`.
         *
         * @param domain The domain to retrieve the [RetrievedAggregator] from.
         * @param loader An optional [CsafLoader] instance. Defaults to [lazyLoader].
         * @return An instance of [RetrievedAggregator], wrapped in a [Result] monad, if successful.
         *   A failed [Result] wrapping the thrown [Throwable] in case of an error.
         */
        suspend fun fromDomain(
            domain: String,
            loader: CsafLoader = lazyLoader,
        ): Result<RetrievedAggregator> {
            val ctx = RetrievalContext()
            val wellKnownPath = "https://$domain/.well-known/csaf-aggregator/aggregator.json"
            return loader
                .fetchAggregator(wellKnownPath, ctx)
                .mapCatching { a -> RetrievedAggregator(a).also { it.validate(ctx) } }
                .recoverCatching { e ->
                    throw RetrievalException("Failed to load CSAF Aggregator from $domain", e)
                }
        }
    }
}
