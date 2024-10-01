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
import io.github.csaf.sbom.generated.Aggregator
import io.github.csaf.sbom.generated.Csaf
import io.github.csaf.sbom.generated.Provider
import io.github.csaf.validation.Validatable
import io.github.csaf.validation.ValidationContext
import io.github.csaf.validation.ValidationException
import io.github.csaf.validation.ValidationFailed
import io.github.csaf.validation.roles.CSAFProviderRole
import io.github.csaf.validation.roles.CSAFPublisherRole
import io.github.csaf.validation.roles.CSAFTrustedProviderRole
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.java.Java
import io.ktor.client.request.*
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.request
import java.util.Date

// TODO(oxisto): This needs to be moved to our requirements/validation API
fun checkForTls(response: HttpResponse): Boolean {
    response.request
    return true
}

class RetrievedAggregator(override val json: Aggregator) : Validatable<Aggregator>

/**
 * This class represents a "retrieved" provider (i.e., the roles "publisher", "provider" and
 * "trusted provider"), including its metadata (in the form of [Provider]) as well as functionality
 * to retrieve its documents.
 */
class RetrievedProvider(override val json: Provider, var lastRetrieved: Date? = null) :
    Validatable<Provider> {

    /**
     * This function fetches all CSAF documents that are listed by this provider. Optionally, this
     * can be filtered.
     */
    fun fetchDocuments(from: Date? = null): List<Result<RetrievedDocument>> {
        // TODO: actually return documents
        return listOf()
    }

    companion object {
        /**
         * Retrieves one or more provider-metadata.json documents (represented by the [Provider]
         * data class) from a domain according to the
         * [retrieval rules](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#731-finding-provider-metadatajson).
         */
        suspend fun from(
            domain: String,
            engine: HttpClientEngine = Java.create()
        ): Result<RetrievedProvider> {
            val loader = CsafLoader(engine)

            // First, we need to check, if a well-known URL exists
            val wellKnownPath = "https://$domain/.well-known/csaf/provider-metadata.json"
            val result = loader.fetchProvider(wellKnownPath)
            if (result.isFailure) {
                return Result.failure(result.exceptionOrNull()!!)
            }

            // TODO: fetch from security.txt
            // TODO: fetch from DNS path if 1 or 2 not works
            // TODO: choose one of the provider metadata

            val provider = RetrievedProvider(result.getOrThrow(), Date())

            // We need to validate the provider according to its "role" (publisher, provider,
            // trusted provider)
            var role =
                when (provider.json.role) {
                    Provider.Role.csaf_publisher -> CSAFPublisherRole()
                    Provider.Role.csaf_provider -> CSAFProviderRole()
                    Provider.Role.csaf_trusted_provider -> CSAFTrustedProviderRole()
                }

            val ctx = ProviderValidationContext(provider)
            val validationResult = role.check(ctx)
            if (validationResult is ValidationFailed) {
                return Result.failure(ValidationException())
            }

            return Result.success(provider)
        }
    }
}

/** This class represents a "retrieved" CSAF document. */
class RetrievedDocument(override val json: Csaf) : Validatable<Csaf> {

    var lastRetrieved: Date? = null
    // TODO: other stuff, like ASC, signatures, etc.

}

class ProviderValidationContext(override val something: RetrievedProvider) :
    ValidationContext<RetrievedProvider>

class DocumentValidationContext(override val something: RetrievedDocument) :
    ValidationContext<RetrievedDocument>
