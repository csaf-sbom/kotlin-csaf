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
package io.github.csaf.validation

import io.ktor.client.statement.HttpResponse

/**
 * This [ValidationContext] holds all the necessary information that is needed to validate a
 * validatable object. According to the requirements in the specification we probably need access to
 * the following information:
 * - The (parsed) JSON containing the provider metadata; see [ValidationContext.validatable]
 * - The filename of the JSON
 * - The URL where it was downloaded (both to check whether a TLP:WHITE is accessible and/or a
 *   TLP:RED is not accessible and whether TLS is used); see [ValidationContext.httpResponse]
 * - The HTTP headers used in the HTTP communication to check for redirects; or the complete HTTP
 *   request; see [ValidationContext.httpResponse])
 */
open class ValidationContext(var validatable: Validatable? = null) {

    // TODO(oxisto): This should be moved to the provider validation context
    enum class DataSource {
        WELL_KNOWN,
        SECURITY_TXT,
        DNS
    }

    var dataSource: DataSource? = null

    /** The HTTP response used to retrieve the [validatable]. */
    var httpResponse: HttpResponse? = null
}
