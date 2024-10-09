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
import io.github.csaf.sbom.validation.ValidationException
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.roles.CSAFProviderRole
import io.github.csaf.sbom.validation.roles.CSAFPublisherRole
import io.github.csaf.sbom.validation.roles.CSAFTrustedProviderRole
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.future.future

/**
 * This class represents a "retrieved" provider (i.e., the roles "publisher", "provider" and
 * "trusted provider"), including its metadata (in the form of [Provider]) as well as functionality
 * to retrieve its documents.
 */
class RetrievedProvider(val json: Provider) {

    /**
     * The role of this [RetrievedProvider] (publisher, provider, trusted provider), required for
     * checking the validity of the provider itself and the documents downloaded by it.
     */
    private val role
        get() =
            when (json.role) {
                Provider.Role.csaf_publisher -> CSAFPublisherRole
                Provider.Role.csaf_provider -> CSAFProviderRole
                Provider.Role.csaf_trusted_provider -> CSAFTrustedProviderRole
            }

    /**
     * Validates this [RetrievedProvider] according to the CSAF standard.
     *
     * @param validationContext The validation context used for validation.
     */
    fun validate(validationContext: ValidationContext) {
        role.checkRole(validationContext).let { vr ->
            if (vr is ValidationFailed) {
                throw ValidationException(vr)
            }
        }
    }

    /** This function fetches all CSAF documents that are listed by this provider. */
    suspend fun fetchDocuments(loader: CsafLoader = lazyLoader): List<Result<RetrievedDocument>> {
        @Suppress("SimpleRedundantLet")
        return json.distributions?.let { distributions ->
            distributions
                .mapNotNull { distribution ->
                    distribution.directory_url?.let { it.toString().trimEnd('/') }
                }
                .mapAsync { directoryUrl ->
                    val indexUrl = "$directoryUrl/index.txt"
                    loader
                        .fetchText(indexUrl)
                        .fold(
                            { index ->
                                index.lines().mapAsync { line ->
                                    val csafUrl = "$directoryUrl/$line"
                                    RetrievedDocument.from(csafUrl, loader, this.role)
                                }
                            },
                            { e ->
                                listOf(
                                    Result.failure(
                                        Exception(
                                            "Failed to fetch index.txt from directory at $directoryUrl",
                                            e
                                        )
                                    )
                                )
                            }
                        )
                }
                .flatten()
        } ?: emptyList()
    }

    @Suppress("unused")
    @JvmOverloads
    fun fetchDocumentsAsync(
        loader: CsafLoader = lazyLoader
    ): CompletableFuture<List<ResultCompat<RetrievedDocument>>> {
        return ioScope.future { fetchDocuments(loader).map { ResultCompat(it) } }
    }

    companion object {
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
         */
        suspend fun from(
            domain: String,
            loader: CsafLoader = lazyLoader
        ): Result<RetrievedProvider> {
            val ctx = ValidationContext()
            // TODO: Only the last error will be available in result. We should do some logging.
            // First, we need to check if a .well-known URL exists.
            val wellKnownPath = "https://$domain/.well-known/csaf/provider-metadata.json"
            return loader
                .fetchProvider(wellKnownPath, ctx)
                .onSuccess { ctx.dataSource = ValidationContext.DataSource.WELL_KNOWN }
                .mapCatching { p -> RetrievedProvider(p).also { it.validate(ctx) } }
                .recoverCatching {
                    // If failure, we fetch CSAF fields from security.txt and try observed URLs
                    // one-by-one.
                    loader.fetchSecurityTxtCsafUrls(domain).getOrThrow().firstNotNullOf { entry ->
                        loader
                            .fetchProvider(entry, ctx)
                            .onSuccess {
                                ctx.dataSource = ValidationContext.DataSource.SECURITY_TXT
                            }
                            .mapCatching { p -> RetrievedProvider(p).also { it.validate(ctx) } }
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
                        .mapCatching { p -> RetrievedProvider(p).also { it.validate(ctx) } }
                        .getOrThrow()
                }
        }
    }
}
