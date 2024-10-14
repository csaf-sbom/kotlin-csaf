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
import io.github.csaf.sbom.validation.ValidationContext
import io.github.csaf.sbom.validation.roles.CSAFAggregatorRole
import io.github.csaf.sbom.validation.roles.CSAFListerRole

/**
 * This class represents a wrapper around a [Aggregator] document, that provides functionality for
 * parsing the metadata about an aggregator from a location, including validation according to the
 * specification.
 *
 * This class is not yet complete.
 */
class RetrievedAggregator(val json: Aggregator) : Validatable {

    /**
     * The role of this [RetrievedAggregator] (lister, aggregator), required for checking the
     * validity of the aggregator itself and the Provider instances downloaded by it.
     */
    override val role
        get() =
            when (json.aggregator.category) {
                Aggregator.Category.lister -> CSAFListerRole
                Aggregator.Category.aggregator -> CSAFAggregatorRole
            }

    companion object {
        /**
         * Retrieves an [Aggregator] from a given [url].
         *
         * @param url The URL where to retrieve the [Aggregator] from.
         * @param loader An instance of [CsafLoader].
         * @return An instance of [RetrievedAggregator], wrapped in a [Result] monad, if successful.
         *   A failed [Result] wrapping the thrown [Throwable] in case of an error.
         */
        suspend fun from(
            url: String,
            loader: CsafLoader = CsafLoader.lazyLoader
        ): Result<RetrievedAggregator> {
            val ctx = ValidationContext()
            val mapAndValidateAggregator = { a: Aggregator ->
                RetrievedAggregator(a).also { it.validate(ctx) }
            }
            return loader
                .fetchAggregator(url, ctx)
                .mapCatching(mapAndValidateAggregator)
                .recoverCatching { e ->
                    throw Exception("Failed to load CSAF Aggregator from $url", e)
                }
        }
    }
}
