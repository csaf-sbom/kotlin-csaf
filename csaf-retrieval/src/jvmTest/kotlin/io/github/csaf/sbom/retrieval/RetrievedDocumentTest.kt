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

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RetrievedDocumentTest {

    @Test
    fun `fromJson should successfully parse valid CSAF JSON`() {
        // Path to the valid CSAF JSON
        val validJson =
            javaClass.classLoader
                ?.getResource("example.com/directory/2022/bsi-2022-0001.json")
                ?.readText() ?: throw IllegalStateException("Failed to load valid CSAF JSON")

        // Call the method
        val result = RetrievedDocument.fromJson(validJson)

        // Assert success
        assertTrue(result.isSuccess, "Parsing should succeed for valid CSAF JSON")
        val document = result.getOrNull()
        assertNotNull(document, "The RetrievedDocument should not be null")
    }

    @Test
    fun `fromJson should fail with invalid JSON`() {
        // Define an invalid JSON string
        val invalidJson = "{ \"invalid\": true, }" // Malformed JSON

        // Call the method
        val result = RetrievedDocument.fromJson(invalidJson)

        // Assert failure
        assertTrue(result.isFailure, "Parsing should fail for invalid JSON")
        val exception = result.exceptionOrNull()
        assertNotNull(exception, "A failure result should contain an exception")
    }
}
