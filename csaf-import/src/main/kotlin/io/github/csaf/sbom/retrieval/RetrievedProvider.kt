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

import io.github.csaf.sbom.CsafLoader
import io.github.csaf.sbom.CsafLoader.Companion.lazyLoader
import io.github.csaf.sbom.generated.Provider
import io.github.csaf.sbom.mapAsync
import io.github.csaf.validation.Role
import io.github.csaf.validation.Validatable
import io.github.csaf.validation.ValidationContext
import io.github.csaf.validation.ValidationException
import io.github.csaf.validation.ValidationFailed
import io.github.csaf.validation.roles.CSAFProviderRole
import io.github.csaf.validation.roles.CSAFPublisherRole
import io.github.csaf.validation.roles.CSAFTrustedProviderRole
import io.ktor.client.statement.*
import me.him188.kotlin.jvm.blocking.bridge.JvmBlockingBridge

/**
 * This class represents a "retrieved" provider (i.e., the roles "publisher", "provider" and
 * "trusted provider"), including its metadata (in the form of [Provider]) as well as functionality
 * to retrieve its documents.
 */
class RetrievedProvider(override val json: Provider, val role: Role) : Validatable {

    /** This function fetches all CSAF documents that are listed by this provider. */
    @JvmBlockingBridge
    suspend fun fetchDocuments(loader: CsafLoader = lazyLoader): List<Result<RetrievedDocument>> {
        return json.distributions
            ?.mapNotNull { it.directory_url?.toString()?.trimEnd('/') }
            ?.mapAsync { directoryUrl ->
                val indexUrl = "$directoryUrl/index.txt"
                loader
                    .fetchText(indexUrl)
                    .fold(
                        { index ->
                            index.lines().mapAsync { line ->
                                val csafUrl = "$directoryUrl/$line"
                                RetrievedDocument.from(csafUrl, loader, this)
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
            ?.flatten() ?: emptyList()
    }

    companion object {
        /**
         * Retrieves one or more provider-metadata.json documents (represented by the [Provider]
         * data class) from a domain according to the
         * [retrieval rules](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#731-finding-provider-metadatajson).
         */
        @JvmBlockingBridge
        suspend fun from(
            domain: String,
            loader: CsafLoader = lazyLoader
        ): Result<RetrievedProvider> {
            val ctx = ValidationContext()
            // Closure for providing HttpResponse to ValidationContext.
            val ctxEnrichment = { response: HttpResponse -> ctx.httpResponse = response }
            // TODO: Only the last error will be available in result. We should do some logging.
            // First, we need to check if a .well-known URL exists.
            val wellKnownPath = "https://$domain/.well-known/csaf/provider-metadata.json"
            return loader
                .fetchProvider(wellKnownPath, ctxEnrichment)
                .map { it.also { ctx.dataSource = ValidationContext.DataSource.WELL_KNOWN } }
                .recoverCatching {
                    // If failure, we fetch CSAF fields from security.txt and try observed URLs
                    // one-by-one.
                    loader.fetchSecurityTxtCsafUrls(domain).getOrThrow().firstNotNullOf {
                        loader.fetchProvider(it, ctxEnrichment).getOrNull()?.also {
                            ctx.dataSource = ValidationContext.DataSource.SECURITY_TXT
                        }
                    }
                }
                .recoverCatching {
                    // If still failure, we try to fetch the provider directly via HTTPS request to
                    // "csaf.data.security.domain.tld", see
                    // https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7110-requirement-10-dns-path.
                    loader
                        .fetchProvider("https://csaf.data.security.$domain", ctxEnrichment)
                        .getOrThrow()
                        .also { ctx.dataSource = ValidationContext.DataSource.DNS }
                }
                .mapCatching { providerMeta ->
                    // We need to validate the provider according to its "role" (publisher,
                    // provider, trusted provider).
                    val role =
                        when (providerMeta.role) {
                            Provider.Role.csaf_publisher -> CSAFPublisherRole()
                            Provider.Role.csaf_provider -> CSAFProviderRole()
                            Provider.Role.csaf_trusted_provider -> CSAFTrustedProviderRole()
                        }
                    val provider =
                        RetrievedProvider(providerMeta, role = role).also { ctx.validatable = it }

                    val validationResult = role.checkRole(ctx)
                    if (validationResult is ValidationFailed) {
                        throw ValidationException(validationResult)
                    }

                    provider
                }
        }
    }
}
