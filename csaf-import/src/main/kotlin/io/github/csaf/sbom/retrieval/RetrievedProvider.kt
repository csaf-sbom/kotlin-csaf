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
import io.github.csaf.sbom.schema.generated.Provider
import io.github.csaf.sbom.validation.ValidationContext
import io.github.csaf.sbom.validation.roles.CSAFProviderRole
import io.github.csaf.sbom.validation.roles.CSAFPublisherRole
import io.github.csaf.sbom.validation.roles.CSAFTrustedProviderRole
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.stream.Stream
import java.util.stream.StreamSupport
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.produce
import kotlinx.coroutines.channels.toList
import kotlinx.coroutines.future.future

/**
 * This class represents a "retrieved" provider (i.e., the roles "publisher", "provider" and
 * "trusted provider"), including its metadata (in the form of [Provider]) as well as functionality
 * to retrieve its documents.
 */
class RetrievedProvider(val json: Provider) : Validatable {

    /**
     * The role of this [RetrievedProvider] (publisher, provider, trusted provider), required for
     * checking the validity of the provider itself and the documents downloaded by it.
     */
    override val role
        get() =
            when (json.role) {
                Provider.Role.csaf_publisher -> CSAFPublisherRole
                Provider.Role.csaf_provider -> CSAFProviderRole
                Provider.Role.csaf_trusted_provider -> CSAFTrustedProviderRole
            }

    /**
     * This function fetches all directory indices referenced by this provider.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return The fetched [Result]s, representing index contents or fetch errors.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    fun fetchDocumentIndices(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY
    ): ReceiveChannel<Pair<String, Result<String>>> {
        @Suppress("SimpleRedundantLet")
        val directoryUrls =
            (json.distributions ?: emptySet()).mapNotNull { distribution ->
                distribution.directory_url?.let { it.toString().trimEnd('/') }
            }
        // This channel collects up to `channelCapacity` directory indices concurrently.
        val indexChannel =
            ioScope.produce(capacity = channelCapacity) {
                for (directoryUrl in directoryUrls) {
                    send(directoryUrl to async { loader.fetchText("$directoryUrl/index.txt") })
                }
            }
        // This terminal channel is a simple "rendezvous channel" for awaiting the Results.
        return ioScope.produce {
            for ((directoryUrl, indexDeferred) in indexChannel) {
                send(directoryUrl to indexDeferred.await())
            }
        }
    }

    /**
     * This function sums up the expected number of [RetrievedDocument]s that will be fetched from
     * this Provider.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return The expected number of [RetrievedDocument]s provided.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun countExpectedDocuments(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY
    ): Int {
        val indexChannel = fetchDocumentIndices(loader, channelCapacity)
        // This second channel collects up to `channelCapacity` Results concurrently, which
        // represent CSAF Documents or errors from fetching or validation.
        val documentCountChannel =
            ioScope.produce(capacity = channelCapacity) {
                for ((_, indexResult) in indexChannel) {
                    indexResult.onSuccess { send(it.lines().size) }
                }
            }
        // This terminal channel is a simple "rendezvous channel" for awaiting the Results.
        return documentCountChannel.toList().sum()
    }

    /**
     * This function fetches all CSAF documents that are listed by this provider.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return The fetched [Result]s, representing [RetrievedDocument]s or fetch/validation errors.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    fun fetchDocuments(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY
    ): ReceiveChannel<Result<RetrievedDocument>> {
        val indexChannel = fetchDocumentIndices(loader, channelCapacity)
        // This second channel collects up to `channelCapacity` Results concurrently, which
        // represent CSAF Documents or errors from fetching or validation.
        val documentJobChannel =
            ioScope.produce<Deferred<Result<RetrievedDocument>>>(capacity = channelCapacity) {
                for ((directoryUrl, indexResult) in indexChannel) {
                    indexResult.fold(
                        { index ->
                            index.lines().map { line ->
                                send(
                                    async {
                                        val csafUrl = "$directoryUrl/$line"
                                        RetrievedDocument.from(csafUrl, loader, role)
                                    }
                                )
                            }
                        },
                        { e ->
                            send(
                                async {
                                    Result.failure(
                                        Exception(
                                            "Failed to fetch index.txt from directory at $directoryUrl",
                                            e
                                        )
                                    )
                                }
                            )
                        }
                    )
                }
            }
        // This terminal channel is a simple "rendezvous channel" for awaiting the Results.
        return ioScope.produce {
            for (documentJob in documentJobChannel) {
                send(documentJob.await())
            }
        }
    }

    /**
     * This method provides the [Result]s of `fetchDocuments()` as a Java [Stream] for usage in
     * non-Kotlin environments.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return The fetched [Result]s, representing [RetrievedDocument]s or fetch/validation errors,
     *   wrapped into [ResultCompat] for Java compatibility.
     */
    @Suppress("unused")
    @JvmOverloads
    fun streamDocuments(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY
    ): Stream<ResultCompat<RetrievedDocument>> {
        val channel = fetchDocuments(loader, channelCapacity)
        val iterator =
            object : Iterator<ResultCompat<RetrievedDocument>> {
                val channelIterator = channel.iterator()

                override fun hasNext() = runBlocking { channelIterator.hasNext() }

                override fun next() = runBlocking { ResultCompat(channelIterator.next()) }
            }
        return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(iterator, Spliterator.NONNULL),
            false
        )
    }

    /**
     * This function sums up the expected number of [RetrievedDocument]s that will be fetched from
     * this Provider, blocking the calling Thread for Java compatiblity.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return The expected number of [RetrievedDocument]s provided.
     */
    @Suppress("unused")
    @JvmOverloads
    fun countExpectedDocumentsBlocking(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY
    ) = runBlocking { countExpectedDocuments(loader, channelCapacity) }

    companion object {
        const val DEFAULT_CHANNEL_CAPACITY = 256
        private val ioScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

        @Suppress("unused")
        @JvmStatic
        @JvmOverloads
        fun fromAsync(
            domain: String,
            loader: CsafLoader = lazyLoader
        ): CompletableFuture<RetrievedProvider> {
            return ioScope.future { from(domain, loader).getOrThrow() }
        }

        /**
         * Retrieves one or more provider-metadata.json documents (represented by the [Provider]
         * data class) from a domain according to the
         * [retrieval rules](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#731-finding-provider-metadatajson).
         *
         * [CSAF standard section
         * 7.1.8](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#718-requirement-8-securitytxt)
         * states that "It is possible to advertise more than one provider-metadata.json by adding
         * multiple CSAF fields [...] However, **this SHOULD NOT be done and removed as soon as
         * possible.**", plus "**If one of the URLs fulfills requirement 9, this MUST be used as the
         * first CSAF entry in the security.txt.**"
         *
         * That means, if we do not return more than one valid Provider, then the first `CSAF` entry
         * in `security.txt` is guaranteed to be identical to the `.well-known` URL, hence
         * resolution of `security.txt` in that case is useless **unless** we want to change our API
         * such that it may resolve multiple `Provider`s for an input domain.
         */
        suspend fun from(
            domain: String,
            loader: CsafLoader = lazyLoader
        ): Result<RetrievedProvider> {
            val ctx = ValidationContext()
            val mapAndValidateProvider = { p: Provider ->
                RetrievedProvider(p).also { it.validate(ctx) }
            }
            // TODO: Only the last error will be available in result. We should do some logging.
            // First, we need to check if a .well-known URL exists.
            val wellKnownPath = "https://$domain/.well-known/csaf/provider-metadata.json"
            return loader
                .fetchProvider(wellKnownPath, ctx)
                .onSuccess { ctx.dataSource = ValidationContext.DataSource.WELL_KNOWN }
                .mapCatching(mapAndValidateProvider)
                .recoverCatching {
                    // If failure, we fetch CSAF fields from security.txt and try observed URLs
                    // one-by-one.
                    loader.fetchSecurityTxtCsafUrls(domain).getOrThrow().firstNotNullOf { entry ->
                        loader
                            .fetchProvider(entry, ctx)
                            .onSuccess {
                                ctx.dataSource = ValidationContext.DataSource.SECURITY_TXT
                            }
                            .mapCatching(mapAndValidateProvider)
                            .getOrNull()
                    }
                }
                .recoverCatching {
                    // If still failure, we try to fetch the provider directly via HTTPS request to
                    // "csaf.data.security.domain.tld", see
                    // https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7110-requirement-10-dns-path.
                    loader
                        .fetchProvider("https://csaf.data.security.$domain", ctx)
                        .onSuccess { ctx.dataSource = ValidationContext.DataSource.DNS }
                        .mapCatching(mapAndValidateProvider)
                        .getOrThrow()
                }
        }
    }
}
