/*
 * Copyright (c) 2025, The Authors. All rights reserved.
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

import io.ktor.client.plugins.ResponseException
import io.ktor.client.statement.request

class RetrievalException(message: String, cause: Throwable) : RuntimeException(message, cause) {
    val url: String? =
        if (cause is ResponseException) {
            cause.response.request.url.toString()
        } else {
            null
        }
}
