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

import io.github.csaf.sbom.generated.Csaf
import io.github.csaf.sbom.generated.Provider
import io.github.csaf.validation.ValidationContext
import io.ktor.client.statement.*
import io.ktor.http.*

// TODO(oxisto): This needs to be moved to our requirements/validation API
fun checkForTls(response: HttpResponse) = response.request.url.protocol == URLProtocol.HTTPS

/**
 * This [ValidationContext] holds all the necessary information that is needed to validate a
 * provider. According to the requirements in the specification we probably need access to the
 * following information:
 * - The (parsed) JSON containing the provider metadata
 * - The filename of the JSON
 * - The URL where it was downloaded (both to check whether a TLP:WHITE is accessible and/or a
 *   TLP:RED is not accessible and whether TLS is used)
 * - The HTTP headers used in the HTTP communication to check for redirects; or the complete HTTP
 *   request
 */
class ProviderValidationContext(validatable: RetrievedProvider? = null) :
    ValidationContext<Provider, RetrievedProvider>(validatable) {}

class DocumentValidationContext(validatable: RetrievedDocument? = null) :
    ValidationContext<Csaf, RetrievedDocument>(validatable)
