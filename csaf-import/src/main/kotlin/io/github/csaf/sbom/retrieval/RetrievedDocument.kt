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
import io.github.csaf.sbom.validation.Validatable
import io.github.csaf.sbom.validation.ValidationContext
import io.github.csaf.sbom.validation.ValidationException
import io.github.csaf.sbom.validation.ValidationFailed
import io.ktor.client.statement.HttpResponse

/** This class represents a "retrieved" CSAF document. */
class RetrievedDocument(override val json: Csaf, val sourceUrl: String) : Validatable {

    // TODO: other stuff, like import time, ASC, signatures, etc.

    companion object {
        suspend fun from(
            documentUrl: String,
            loader: CsafLoader = lazyLoader,
            provider: RetrievedProvider
        ): Result<RetrievedDocument> {
            val ctx = ValidationContext()
            val ctxEnrichment = { response: HttpResponse -> ctx.httpResponse = response }
            return loader
                .fetchDocument(documentUrl, ctxEnrichment)
                .mapCatching {
                    RetrievedDocument(it, documentUrl).also { doc ->
                        ctx.validatable = doc

                        provider.role.checkDocument(ctx).let { vr ->
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
