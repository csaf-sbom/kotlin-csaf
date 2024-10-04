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
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.Role
import io.github.csaf.sbom.validation.Validatable
import io.github.csaf.sbom.validation.ValidationContext
import io.github.csaf.sbom.validation.ValidationException
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.roles.CSAFTrustedProviderRole

/**
 * This class represents a wrapper around a [Csaf] document, that provides functionality for
 * fetching a document from a location, including validation according to the specification.
 */
class RetrievedDocument(override val json: Csaf, val sourceUrl: String) : Validatable {

    companion object {
        /**
         * Retrieves a specific CSAF document from a [documentUrl]. The document will be validated
         * according to [providerRole].
         *
         * @param documentUrl The URL where to retrieve the document from.
         * @param loader An instance of [CsafLoader].
         * @param providerRole An instance of a [Role]. This is needed in order to correctly
         *   validate the document according to the role where it is hosted (e.g.,
         *   [CSAFTrustedProviderRole]).
         * @return An instance of [RetrievedDocument], wrapped in a [Result] monad, if successful. A
         *   failed [Result] wrapping the thrown [Throwable] in case of an error.
         */
        suspend fun from(
            documentUrl: String,
            loader: CsafLoader = lazyLoader,
            providerRole: Role
        ): Result<RetrievedDocument> {
            val ctx = ValidationContext()
            return loader
                .useValidationContext(ctx)
                .fetchDocument(documentUrl)
                .mapCatching {
                    RetrievedDocument(it, documentUrl).also { doc ->
                        ctx.validatable = doc

                        providerRole.checkDocument(ctx).let { vr ->
                            if (vr is ValidationFailed) {
                                throw ValidationException(vr)
                            }
                        }
                    }
                }
                .recoverCatching { e ->
                    throw Exception("Failed to fetch CSAF document from $documentUrl", e)
                }
        }
    }
}
