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

import io.csaf.schema.generated.Aggregator
import io.csaf.schema.generated.Csaf
import io.csaf.schema.generated.Provider
import io.csaf.schema.generated.ROLIEFeed
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.HttpRequestRetry
import io.ktor.client.plugins.ResponseException
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.serialization.kotlinx.json.*

/**
 * This function needs to be implemented by each platform to provide a platform-specific
 * [HttpClientEngine] for ktor.
 */
expect fun defaultHttpClientEngine(): HttpClientEngine

/**
 * Creates a default [HttpClient] with retry logic and JSON support.
 *
 * @param engine The HTTP engine to use. Defaults to [defaultHttpClientEngine].
 * @param maxRetries The amount of times that HTTP requests are retried on errors.
 * @param retryBase The exponent for exponential delay.
 * @param retryBaseDelayMs Base delay in ms.
 * @param retryMaxDelayMs Max delay in ms.
 * @return Configured [HttpClient].
 */
@JvmOverloads
fun defaultHttpClient(
    engine: HttpClientEngine = defaultHttpClientEngine(),
    maxRetries: Int = 3,
    retryBase: Double = 2.0,
    retryBaseDelayMs: Long = 1000,
    retryMaxDelayMs: Long = 60000,
): HttpClient {
    return HttpClient(engine) {
        expectSuccess = true

        install(ContentNegotiation) { json() }

        install(HttpRequestRetry) {
            retryOnServerErrors(maxRetries = maxRetries)
            // Retry on HTTP Too Many Requests
            retryIf(maxRetries = maxRetries) { _, response -> response.status.value == 429 }
            // Use exponential backoff
            exponentialDelay(
                base = retryBase,
                baseDelayMs = retryBaseDelayMs,
                maxDelayMs = retryMaxDelayMs,
            )
        }
    }
}

/**
 * A helper class with async functions to retrieve certain kinds of CSAF-related data.
 *
 * @param engine An instance of HttpClientEngine for the httpClient. Defaults to
 *   [defaultHttpClientEngine].
 * @param client An instance of HttpClient for HTTP(S) data retrieval via Ktor. Defaults to
 *   [defaultHttpClient].
 */
class CsafLoader
@JvmOverloads
constructor(engine: HttpClientEngine? = null, client: HttpClient? = null) {
    private val httpClient: HttpClient =
        client ?: defaultHttpClient(engine ?: defaultHttpClientEngine())

    /**
     * Helper function for all other functions defined below. Performs a get request and returns the
     * [HttpResponse], invoking [responseCallback] if not null.
     *
     * @param url The URL to request data from.
     * @param responseCallback An optional callback to further evaluate the [HttpResponse].
     * @return The resulting [HttpResponse].
     */
    private suspend inline fun <reified T> get(
        url: String,
        crossinline responseCallback: ((HttpResponse) -> Unit),
    ): T {
        try {
            return httpClient.get(url).also { responseCallback(it) }.body()
        } catch (e: ResponseException) {
            responseCallback.invoke(e.response)
            throw e
        }
    }

    /**
     * Fetch and parse an aggregator JSON document from a given URL.
     *
     * @param url The URL where the aggregator document is found.
     * @param ctx An optional [RetrievalContext] that is automatically filled with the HTTP response
     *   and body of the calls made in this function.
     * @return An instance of [Aggregator], wrapped in a [Result] monad, if successful. A failed
     *   [Result] wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchAggregator(url: String, ctx: RetrievalContext? = null): Result<Aggregator> =
        Result.of { get<Aggregator>(url, ctx.responseCallback()).also(ctx.jsonCallback()) }

    /**
     * Fetch and parse a provider JSON document from a given URL.
     *
     * @param url The URL where the provider document is found.
     * @param ctx An optional [RetrievalContext] that is automatically filled with the HTTP response
     *   and body of the calls made in this function.
     * @return An instance of [Provider], wrapped in a [Result] monad, if successful. A failed
     *   [Result] wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchProvider(url: String, ctx: RetrievalContext? = null): Result<Provider> =
        Result.of { get<Provider>(url, ctx.responseCallback()).also(ctx.jsonCallback()) }

    /**
     * Fetch and parse a CSAF JSON document from a given URL.
     *
     * @param url The URL where the CSAF document is found.
     * @param ctx A [RetrievalContext] that is automatically filled with the HTTP response and body
     *   of the calls made in this function.
     * @return An instance of [Csaf], wrapped in a [Result] monad, if successful. A failed [Result]
     *   wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchDocument(url: String, ctx: RetrievalContext): Result<Csaf> =
        Result.of { get<Csaf>(url, ctx.responseCallback()).also(ctx.jsonCallback()) }

    /**
     * Fetch and parse a ROLE feed from a given URL.
     *
     * @param url the URL where the ROLIE feed is found
     * @param responseCallback An optional callback to further evaluate the [HttpResponse].
     * @return The resulting [ROLIEFeed], wrapped in a [Result] monad, if successful. A failed
     *   [Result] wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchROLIEFeed(
        url: String,
        responseCallback: ((HttpResponse) -> Unit)? = null,
    ): Result<ROLIEFeed> = Result.of { get(url, responseCallback ?: {}) }

    /**
     * Fetch an arbitrary URL's content as plain text [String], falling back to UTF-8 if no charset
     * is provided.
     *
     * @param url The URL to fetch plaintext from.
     * @param responseCallback An optional callback to further evaluate the [HttpResponse].
     * @return The resulting text, wrapped in a [Result] monad, if successful. A failed [Result]
     *   wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchText(
        url: String,
        responseCallback: ((HttpResponse) -> Unit)? = null,
    ): Result<String> = Result.of { get(url, responseCallback ?: {}) }

    /**
     * Fetch the `CSAF` fields from a `security.txt` as specified in
     * [CSAF 7.1.8](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#718-requirement-8-securitytxt).
     *
     * @param domain The domain from which to obtain the `security.txt`.
     * @param responseCallback An optional callback to further evaluate the [HttpResponse].
     * @return A list of `https`-URL values (as `String`s) obtained from CSAF fields in
     *   `security.txt`, wrapped in a [Result] monad, if successful. A failed [Result] wrapping the
     *   thrown [Throwable] in case of an error.
     */
    suspend fun fetchSecurityTxtCsafUrls(
        domain: String,
        responseCallback: ((HttpResponse) -> Unit)? = null,
    ) =
        // TODO: A security.txt can be PGP-signed. Signature check not implemented yet.
        //  See https://github.com/csaf-sbom/kotlin-csaf/issues/43
        fetchText("https://$domain/.well-known/security.txt", responseCallback)
            // Try fallback to legacy location.
            .recoverCatching {
                fetchText("https://$domain/security.txt", responseCallback).getOrThrow()
            }
            .mapCatching { securityTxt ->
                securityTxt
                    .lineSequence()
                    .mapNotNull { line ->
                        CSAF_ENTRY_REGEX.matchEntire(line)?.let { it.groupValues[1] }
                    }
                    .toList()
            }

    companion object {
        @JvmStatic val lazyLoader: CsafLoader by lazy { defaultLoaderFactory() }
        internal var defaultLoaderFactory: (() -> CsafLoader) = { CsafLoader() }

        /**
         * Initialize a [CsafLoader] with the provided [HttpClient].
         *
         * @param client [HttpClient] used for preforming requests.
         */
        @JvmStatic fun fromClient(client: HttpClient): CsafLoader = CsafLoader(client = client)

        /**
         * Initialize a [CsafLoader] with the provided [HttpClientEngine].
         *
         * @param engine [HttpClientEngine] passed to default [HttpClient].
         */
        @JvmStatic
        fun fromEngine(engine: HttpClientEngine): CsafLoader = CsafLoader(engine = engine)

        /**
         * Initialize a [CsafLoader] with the provided settings.
         *
         * @param maxRetries The amount of times that HTTP requests are retried on errors.
         * @param retryBase The exponent for exponential delay.
         * @param retryBaseDelayMs Base delay in ms.
         * @param retryMaxDelayMs Max delay in ms.
         * @param engine The HTTP engine to use. Defaults to [defaultHttpClientEngine].
         */
        @JvmStatic
        @JvmOverloads
        fun withSettings(
            maxRetries: Int = 3,
            retryBase: Double = 2.0,
            retryBaseDelayMs: Long = 1000,
            retryMaxDelayMs: Long = 60000,
            engine: HttpClientEngine? = null,
        ): CsafLoader =
            CsafLoader(
                client =
                    defaultHttpClient(
                        engine = engine ?: defaultHttpClientEngine(),
                        maxRetries = maxRetries,
                        retryBase = retryBase,
                        retryBaseDelayMs = retryBaseDelayMs,
                        retryMaxDelayMs = retryMaxDelayMs,
                    )
            )
    }
}
