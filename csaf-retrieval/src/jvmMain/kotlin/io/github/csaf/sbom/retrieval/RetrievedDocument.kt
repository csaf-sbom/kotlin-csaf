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
import io.github.csaf.sbom.retrieval.roles.CSAFPublisherRole
import io.github.csaf.sbom.retrieval.roles.CSAFTrustedProviderRole
import io.github.csaf.sbom.retrieval.roles.Role
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.ValidationFailed
import java.io.InputStream
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.future.future
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream

/**
 * This class represents a wrapper around a [Csaf] document, that provides functionality for
 * fetching a document from a location, including validation according to the specification.
 */
data class RetrievedDocument(
    /** The parsed [Csaf] document */
    val json: Csaf,
    /** The URL where the document was retrieved from. */
    val url: String,
) {

    companion object {
        private val ioScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

        /**
         * Retrieves a specific CSAF document from a given URL, validating it according to the
         * provided role.
         *
         * @param documentUrl The URL where to retrieve the document from.
         * @param loader An instance of [CsafLoader].
         * @param providerRole An instance of a [Role]. This is needed in order to correctly
         *   validate the document according to the role where it is hosted (e.g.,
         *   [CSAFTrustedProviderRole]).
         * @return An instance of [RetrievedDocument], wrapped in a [Result] monad, if successful. A
         *   failed [Result] wrapping the thrown [Throwable] in case of an error.
         */
        suspend fun fromUrl(
            documentUrl: String,
            loader: CsafLoader,
            providerRole: Role,
        ): Result<RetrievedDocument> {
            val ctx = RetrievalContext()
            return loader
                .fetchDocument(documentUrl, ctx)
                .mapCatching {
                    RetrievedDocument(it, documentUrl).also { _ ->
                        providerRole.checkDocument(ctx).let { vr ->
                            if (vr is ValidationFailed) {
                                throw vr.toException()
                            }
                        }
                    }
                }
                .recoverCatching { e ->
                    throw RetrievalException("Failed to load CSAF document from $documentUrl", e)
                }
        }

        /**
         * Retrieves a specific CSAF document asynchronously from a given URL, validating it
         * according to the provided role.
         *
         * @param documentUrl The URL from which the CSAF document will be retrieved.
         * @param loader An instance of [CsafLoader] used for HTTP data retrieval and processing.
         * @param providerRole An instance of [Role], specifying the validation role to be applied
         *   to the retrieved document.
         * @return An instance of [RetrievedDocument], wrapped in a [CompletableFuture] upon
         *   success. In case of an error, the future wraps the thrown [Exception].
         */
        @JvmStatic
        @JvmOverloads
        fun fromUrlAsync(
            documentUrl: String,
            loader: CsafLoader = lazyLoader,
            providerRole: Role = CSAFPublisherRole,
        ): CompletableFuture<RetrievedDocument> =
            ioScope.future { fromUrl(documentUrl, loader, providerRole).getOrThrow() }

        /**
         * Load [RetrievedDocument] from JSON string.
         *
         * @param json JSON String to parse.
         * @param url URL where the document was originally located.
         * @return The result of the CSAF parsing, wrapped in a [ResultCompat] monad.
         */
        @JvmStatic
        fun fromJson(json: String, url: String): ResultCompat<RetrievedDocument> {
            return try {
                ResultCompat.success(RetrievedDocument(Json.decodeFromString<Csaf>(json), url))
            } catch (t: Throwable) {
                ResultCompat.failure(t)
            }
        }

        /**
         * Load [RetrievedDocument] from JSON-yielding InputStream.
         *
         * @param stream InputStream yielding JSON to parse.
         * @param url URL where the document was originally located.
         * @return The result of the CSAF parsing, wrapped in a [ResultCompat] monad.
         */
        @OptIn(ExperimentalSerializationApi::class)
        @JvmStatic
        fun fromJson(stream: InputStream, url: String): ResultCompat<RetrievedDocument> {
            return try {
                ResultCompat.success(RetrievedDocument(Json.decodeFromStream<Csaf>(stream), url))
            } catch (t: Throwable) {
                ResultCompat.failure(t)
            }
        }
    }
}
