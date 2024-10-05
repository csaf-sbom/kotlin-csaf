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

import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

@KoverIgnore("Entry point for demo purposes only")
fun main(args: Array<String>) {
    runBlocking {
        // Create a new "RetrievedProvider" from a domain. This will automatically discover a
        // suitable provider-metadata.json
        val provider = RetrievedProvider.from(args[0]).getOrThrow()

        print("Discovered provider-metadata.json @ ${provider.json.canonical_url}\n")

        // Retrieve all documents from all feeds. Note: we currently only support index.txt
        async {
            val documentResults = provider.fetchDocuments()
            documentResults.forEach { it ->
                it.onSuccess { doc ->
                        // The resulting document is a "Csaf" type, which contains the
                        // representation defined
                        // in the JSON schema
                        print("Fetched document with ID ${doc.json.document.tracking.id}\n")
                    }
                    .onFailure { ex ->
                        print("Could not fetch document: ${ex.message}, ${ex.cause}\n")
                    }
            }
        }
    }
}
