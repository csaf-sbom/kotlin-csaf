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
package io.github.csaf.sbom

import io.github.csaf.sbom.generated.Provider
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.java.Java
import io.ktor.client.request.*
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.request

/**
 * Retrieves one or more provider-metadata.json documents (represented by the [Provider] data class)
 * from a domain according to the
 * [retrieval rules](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#731-finding-provider-metadatajson).
 */
suspend fun retrieveProviderFromDomain(
    domain: String,
    engine: HttpClientEngine = Java.create()
): Result<List<Provider>> {
    val client = HttpClient(engine)

    // First, we need to check, if a well-known URL exists
    val wellKnownPath = "https://$domain/.well-known/csaf/provider-metadata.json"

    val response = client.get(wellKnownPath)

    return Result.success(listOf())
}

// TODO(oxisto): This needs to be moved to our requirements/validation API
fun checkForTls(response: HttpResponse): Boolean {
    response.request
    return true
}
