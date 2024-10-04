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

import io.github.csaf.sbom.schema.generated.Aggregator
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Provider
import io.github.csaf.sbom.validation.ValidationContext
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
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
     * An optional validation context that is automatically filled with the HTTP response of the
     * calls made in this loader. It can be set with [useValidationContext].
     */
    private var ctx: ValidationContext? = null

    private var storeHttpResponseInContext =
        fun(ctx: ValidationContext?) = { response: HttpResponse -> ctx?.httpResponse = response }

    /** Configures [ctx] to be used as a validation context during fetching. */
    fun useValidationContext(ctx: ValidationContext): CsafLoader {
        this.ctx = ctx
        return this
    }

    /**
     * Helper function for all other functions defined below. Performs a get request and returns the
     * [HttpResponse], invoking [responseCallback] if not null.
     *
     * @param url The URL to request data from.
     * @param responseCallback An optional callback to further evaluate the [HttpResponse].
     * @return The resulting [HttpResponse].
     */
    private suspend fun genericGet(
        url: String,
        responseCallback: ((HttpResponse) -> Unit)? = null
    ): HttpResponse {
        val response = httpClient.get(url)
        responseCallback?.invoke(response)
        return response
    }

    /**
     * Fetch and parse an aggregator JSON document from a given URL.
     *
     * @param url The URL where the aggregator document is found.
     * @param responseCallback An optional callback to further evaluate the [HttpResponse].
     * @return An instance of [Aggregator], wrapped in a [Result] monad, if successful. A failed
     *   [Result] wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchAggregator(
        url: String,
        responseCallback: ((HttpResponse) -> Unit)? = null
    ): Result<Aggregator> = Result.of { genericGet(url, responseCallback).body() }

    /**
     * Fetch and parse a provider JSON document from a given URL.
     *
     * @param url The URL where the provider document is found.
     * @return An instance of [Provider], wrapped in a [Result] monad, if successful. A failed
     *   [Result] wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchProvider(url: String): Result<Provider> =
        Result.of { genericGet(url, storeHttpResponseInContext(ctx)).body() }

    /**
     * Fetch and parse a CSAF JSON document from a given URL.
     *
     * @param url The URL where the CSAF document is found.
     * @return An instance of [Csaf], wrapped in a [Result] monad, if successful. A failed [Result]
     *   wrapping the thrown [Throwable] in case of an error.
     */
    suspend fun fetchDocument(url: String): Result<Csaf> =
        Result.of { genericGet(url, storeHttpResponseInContext(ctx)).body() }

    /**
     * Fetch an arbitrary URL's content as plain text [String], falling back to UTF-8 if no charset
     * is provided.
     *
     * @param url The URL to fetch plaintext from.
     * @param responseCallback An optional callback to further evaluate the [HttpResponse].
     * @return The resulting text, wrapped in a [Result] monad, if successful. A failed [Result]
     *   wrapping the thrown [hrowable] in case of an error.
     */
    suspend fun fetchText(
        url: String,
        responseCallback: ((HttpResponse) -> Unit)? = null
    ): Result<String> = Result.of { genericGet(url, responseCallback).bodyAsText() }

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
        responseCallback: ((HttpResponse) -> Unit)? = null
    ) =
        // TODO: A security.txt can be PGP-signed. Signature check not implemented yet.
        //  See https://github.com/csaf-sbom/kotlin-csaf/issues/43
        // TODO: A security.txt can also be at a legacy location.
        //  See https://github.com/csaf-sbom/kotlin-csaf/issues/44
        fetchText("https://$domain/.well-known/security.txt", responseCallback).mapCatching {
            securityTxt ->
            securityTxt
                .lineSequence()
                .mapNotNull { securityTxtCsaf.matchEntire(it)?.groupValues?.get(1) }
                .toList()
        }

    companion object {
        val securityTxtCsaf = Regex("CSAF: (https://.*)")
        val lazyLoader: CsafLoader by lazy { CsafLoader() }
    }
}
