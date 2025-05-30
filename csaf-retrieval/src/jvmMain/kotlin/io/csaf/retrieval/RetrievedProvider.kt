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

import com.github.doyaaaaaken.kotlincsv.dsl.csvReader
import io.csaf.retrieval.CsafLoader.Companion.lazyLoader
import io.csaf.retrieval.roles.CSAFProviderRole
import io.csaf.retrieval.roles.CSAFPublisherRole
import io.csaf.retrieval.roles.CSAFTrustedProviderRole
import io.csaf.schema.generated.Provider
import io.csaf.schema.generated.Provider.Feed
import io.csaf.schema.generated.ROLIEFeed
import io.github.oshai.kotlinlogging.KotlinLogging
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.stream.Stream
import java.util.stream.StreamSupport
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.*
import kotlinx.coroutines.future.future
import kotlinx.datetime.Instant

/**
 * This class represents a "retrieved" provider (i.e., the roles "publisher", "provider" and
 * "trusted provider"), including its metadata (in the form of [Provider]) as well as functionality
 * to retrieve its documents.
 */
@OptIn(ExperimentalCoroutinesApi::class)
data class RetrievedProvider(val json: Provider) : Validatable {

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
     * This function fetches all directory indices or changes.csv files referenced by this provider
     * and sends them to a [ReceiveChannel].
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @param useChangesCsv Load changes.csv files instead of index.txt ones.
     * @return A [ReceiveChannel] containing the fetched [Result]s, representing index contents,
     *   changes.csv contents or fetch errors.
     */
    fun fetchDocumentIndices(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY,
        useChangesCsv: Boolean = false,
    ): ReceiveChannel<Pair<String, Result<String>>> {
        val directoryUrls =
            (json.distributions ?: emptySet()).mapNotNull { distribution ->
                @Suppress("SimpleRedundantLet")
                distribution.directory_url?.let { it.toString().trimEnd('/') }
            }
        // This channel collects up to `channelCapacity` directory indices concurrently.
        val indexChannel =
            ioScope.produce(capacity = channelCapacity) {
                for (directoryUrl in directoryUrls) {
                    val indexFile =
                        if (useChangesCsv) {
                            "$directoryUrl/changes.csv"
                        } else {
                            "$directoryUrl/index.txt"
                        }
                    send(directoryUrl to async { loader.fetchText(indexFile) })
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
     * This function fetches all ROLIE feeds referenced by this provider and sends them to a
     * [ReceiveChannel].
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return A [ReceiveChannel] containing the fetched [Result]s, representing ROLIE feeds'
     *   contents (as [ROLIEFeed]) or fetch errors.
     */
    fun fetchRolieFeeds(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY,
    ): ReceiveChannel<Pair<Feed, Result<ROLIEFeed>>> {
        val feeds = json.distributions?.mapNotNull { it.rolie }?.flatMap { it.feeds } ?: listOf()

        // This channel collects up to `channelCapacity` feeds concurrently.
        val rolieChannel =
            ioScope.produce(capacity = channelCapacity) {
                for (feed in feeds) {
                    send(feed to async { loader.fetchROLIEFeed(feed.url.toString()) })
                }
            }
        // This terminal channel is a simple "rendezvous channel" for awaiting the Results.
        return ioScope.produce {
            for ((feed, feedDeferred) in rolieChannel) {
                send(feed to feedDeferred.await())
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
    suspend fun countExpectedDocuments(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY,
        startingFrom: Instant? = null,
    ): Int {
        return fetchAllDocumentUrls(loader, channelCapacity, startingFrom)
            .toList()
            .filter { it.isSuccess }
            .size
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
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY,
        startingFrom: Instant? = null,
    ): ReceiveChannel<Result<RetrievedDocument>> {
        val documentUrlChannel = fetchAllDocumentUrls(loader, channelCapacity, startingFrom)
        // This second channel collects up to `channelCapacity` Results concurrently, which
        // represent CSAF Documents or errors from fetching or validation.
        val documentJobChannel =
            ioScope.produce<Deferred<Result<RetrievedDocument>>>(capacity = channelCapacity) {
                for (result in documentUrlChannel) {
                    result.fold(
                        { send(async { RetrievedDocument.fromUrl(it, loader, role) }) },
                        { send(async { Result.failure(it) }) },
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
     * Returns a channel that produces all URLs from ROLIE feeds and directory indices without
     * duplicates.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @param startingFrom Optional [Instant] associated with the oldest CSAF document URLs to be
     *   retrieved. If omitted, all document URLs will be fetched.
     * @return
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    fun fetchAllDocumentUrls(
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY,
        startingFrom: Instant? = null,
    ): ReceiveChannel<Result<String>> {
        val urlResultChannel =
            ioScope.produce(capacity = channelCapacity) {
                fetchDocumentUrlsFromIndices(
                    fetchDocumentIndices(loader, channelCapacity, startingFrom != null),
                    startingFrom,
                )
                fetchDocumentUrlsFromRolieFeeds(
                    fetchRolieFeeds(loader, channelCapacity),
                    startingFrom,
                )
            }
        return ioScope.produce {
            val seenUrls = mutableSetOf<String>()
            for (urlResult in urlResultChannel) {
                urlResult.fold(
                    {
                        if (seenUrls.add(it)) {
                            send(Result.success(it))
                        }
                    },
                    { send(Result.failure(it)) },
                )
            }
        }
    }

    /**
     * Sends the URLs obtained from the [indexChannel] to the given [SendChannel]. Assumes CSV input
     * from a changes.csv if [startingFrom] is set, line-separated plain text input from index.txt
     * files otherwise.
     *
     * @param indexChannel The source channel providing directory index data.
     * @param startingFrom Optional [Instant] associated with the oldest CSAF document URLs to be
     *   retrieved from CSV. If null, all document URLs will be fetched (plain index.txt is assumed
     *   in that case).
     * @receiver The target channel where URLs are sent to.
     */
    private suspend fun SendChannel<Result<String>>.fetchDocumentUrlsFromIndices(
        indexChannel: ReceiveChannel<Pair<String, Result<String>>>,
        startingFrom: Instant?,
    ) {
        for ((directoryUrl, indexResult) in indexChannel) {
            indexResult.fold(
                { index ->
                    if (startingFrom != null) {
                        for (line in
                            csvReader {
                                    skipEmptyLine = true
                                    skipMissMatchedRow = true
                                }
                                .readAll(index)) {
                            val (relativePath, timestamp) = line
                            val lastUpdated = Instant.parse(timestamp)
                            if (lastUpdated >= startingFrom) {
                                send(Result.success("$directoryUrl/$relativePath"))
                            }
                        }
                    } else {
                        var lines = index.lines()
                        lines.forEachIndexed { idx, line ->
                            // The common sense is to ignore trailing empty lines (see
                            // https://github.com/oasis-tcs/csaf/issues/919)
                            if (idx == lines.size - 1 && line.isBlank()) {
                                return@forEachIndexed
                            }

                            send(Result.success("$directoryUrl/$line"))
                        }
                    }
                },
                { e ->
                    val fileName =
                        if (startingFrom != null) {
                            "changes.csv"
                        } else {
                            "index.txt"
                        }
                    send(
                        Result.failure(
                            RetrievalException(
                                "Failed to fetch $fileName from directory at $directoryUrl",
                                e,
                            )
                        )
                    )
                },
            )
        }
    }

    /**
     * Sends the URLs obtained from the [rolieChannel] feeds to the given [SendChannel].
     *
     * @param rolieChannel The source channel providing ROLIE feed data.
     * @param startingFrom Optional [Instant] associated with the oldest CSAF document URLs to be
     *   retrieved. If null, all document URLs will be fetched.
     * @receiver The target channel where URLs are sent to.
     */
    private suspend fun SendChannel<Result<String>>.fetchDocumentUrlsFromRolieFeeds(
        rolieChannel: ReceiveChannel<Pair<Feed, Result<ROLIEFeed>>>,
        startingFrom: Instant?,
    ) {
        for ((feed, rolieResult) in rolieChannel) {
            rolieResult.fold(
                { rolie ->
                    rolie.feed.entry.map { entry ->
                        if (startingFrom == null || entry.updated > startingFrom) {
                            send(Result.success(entry.content.src.toString()))
                        }
                    }
                },
                { e ->
                    send(
                        Result.failure(
                            RetrievalException("Failed to fetch ROLIE feed from ${feed.url}", e)
                        )
                    )
                },
            )
        }
    }

    /**
     * This method provides the [Result]s of [fetchDocuments] as a Java [Stream] for usage in
     * non-Kotlin environments.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return The fetched [Result]s, representing [RetrievedDocument]s or fetch/validation errors,
     *   wrapped into [ResultCompat] for Java compatibility.
     */
    @JvmOverloads
    fun streamDocuments(
        startingFrom: Instant? = null,
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY,
    ): Stream<ResultCompat<RetrievedDocument>> {
        val channel = fetchDocuments(loader, channelCapacity, startingFrom)
        val iterator =
            object : Iterator<ResultCompat<RetrievedDocument>> {
                val channelIterator = channel.iterator()

                override fun hasNext() = runBlocking { channelIterator.hasNext() }

                override fun next() = runBlocking { ResultCompat(channelIterator.next()) }
            }
        return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(iterator, Spliterator.NONNULL),
            false,
        )
    }

    /**
     * This function sums up the expected number of [RetrievedDocument]s that will be fetched from
     * this Provider, blocking the calling Thread for Java compatibility.
     *
     * @param loader The instance of [CsafLoader] used for fetching of online resources.
     * @param channelCapacity The capacity of the channels used to buffer parallel fetches. Defaults
     *   to [DEFAULT_CHANNEL_CAPACITY].
     * @return The expected number of [RetrievedDocument]s provided.
     */
    @JvmOverloads
    fun countExpectedDocumentsBlocking(
        startingFrom: Instant? = null,
        loader: CsafLoader = lazyLoader,
        channelCapacity: Int = DEFAULT_CHANNEL_CAPACITY,
    ) = runBlocking { countExpectedDocuments(loader, channelCapacity, startingFrom) }

    companion object {
        const val DEFAULT_CHANNEL_CAPACITY = 256
        private val ioScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        private val log = KotlinLogging.logger {}

        /**
         * Asynchronously retrieves a [RetrievedProvider] based on the given domain.
         *
         * @param domain The domain name to evaluate in order to construct a [RetrievedProvider].
         * @param loader The instance of [CsafLoader] used for fetching necessary online resources.
         *   Defaults to [lazyLoader].
         * @return A future that resolves to a [RetrievedProvider] or an error if the operation
         *   fails.
         */
        @JvmStatic
        @JvmOverloads
        fun fromDomainAsync(domain: String, loader: CsafLoader = lazyLoader) =
            ioScope.future { fromDomain(domain, loader).getOrThrow() }

        /**
         * Creates a [RetrievedProvider] from a provider-metadata.json document (represented by the
         * [Provider] data class) from a domain according to the
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
        suspend fun fromDomain(
            domain: String,
            loader: CsafLoader = lazyLoader,
        ): Result<RetrievedProvider> {
            val ctx = RetrievalContext()
            val errors = mutableListOf<Pair<String, Throwable>>()
            val logAndSaveError = { e: Throwable, message: String ->
                log.info(e) { "$message." }
                errors += message to e
            }
            // First, we need to check if a .well-known URL exists.
            val wellKnownPath = "https://$domain/.well-known/csaf/provider-metadata.json"
            return fromUrlWithContext(wellKnownPath, ctx, loader)
                .recoverCatching {
                    logAndSaveError(it, "Failed to fetch and validate provider via .well-known")
                    // If failure, we fetch CSAF fields from security.txt and try observed URLs
                    // one-by-one.
                    loader.fetchSecurityTxtCsafUrls(domain).getOrThrow().firstNotNullOfOrNull {
                        entry ->
                        fromUrlWithContext(entry, ctx, loader)
                            .onFailure {
                                logAndSaveError(
                                    it,
                                    "Failed to fetch and validate provider via security.txt entry",
                                )
                            }
                            .getOrNull()
                    } ?: throw NoSuchElementException("No valid entry found via security.txt")
                }
                .recoverCatching {
                    logAndSaveError(it, "Failed to fetch and validate provider via security.txt")
                    // If still failure, we try to fetch the provider directly via HTTPS request to
                    // "csaf.data.security.domain.tld", see
                    // https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7110-requirement-10-dns-path.
                    fromUrlWithContext("https://csaf.data.security.$domain", ctx, loader)
                        .getOrThrow()
                }
                .recoverCatching {
                    logAndSaveError(it, "Failed to fetch and validate provider via DNS")
                    throw RetrievalException(
                        "Failed to resolve provider for $domain via all implemented methods:\n" +
                            errors.joinToString("\n") { (message, error) ->
                                "- $message: ${error.message}"
                            },
                        it,
                    )
                }
        }

        /**
         * Asynchronously constructs a [RetrievedProvider] from a JSON found at the specified URL.
         * The result is wrapped into a [CompletableFuture].
         *
         * @param url The URL of the resource to fetch.
         * @param loader An instance of [CsafLoader] used to retrieve the provider. Defaults to
         *   [lazyLoader].
         * @return A future that resolves to a [RetrievedProvider] or an error if the operation
         *   fails.
         */
        @JvmStatic
        @JvmOverloads
        fun fromUrlAsync(url: String, loader: CsafLoader = lazyLoader) =
            ioScope.future { fromUrl(url, loader).getOrThrow() }

        /**
         * Constructs a [RetrievedProvider] from a JSON found at the specified URL.
         *
         * @param url The URL of the provider JSON to fetch.
         * @param loader An instance of [CsafLoader] used to retrieve the provider. Defaults to
         *   [lazyLoader].
         * @return A [Result] containing the retrieved [RetrievedProvider] or an error if the
         *   operation fails.
         */
        suspend fun fromUrl(url: String, loader: CsafLoader = lazyLoader) =
            fromUrlWithContext(url, RetrievalContext(), loader)

        /**
         * Constructs a [RetrievedProvider] from a JSON found at the specified URL, using a
         * pre-existing [RetrievalContext].
         *
         * @param url The URL of the provider JSON to fetch.
         * @param ctx The [RetrievalContext] to use.
         * @param loader An instance of [CsafLoader] used to retrieve the provider.
         * @return A [Result] containing the retrieved [RetrievedProvider] or an error if the
         *   operation fails.
         */
        private suspend fun fromUrlWithContext(
            url: String,
            ctx: RetrievalContext,
            loader: CsafLoader,
        ): Result<RetrievedProvider> {
            return loader.fetchProvider(url, ctx).mapCatching {
                RetrievedProvider(it).also { it.validate(ctx) }
            }
        }
    }
}
