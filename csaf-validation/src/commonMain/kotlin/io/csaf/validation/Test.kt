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
package io.csaf.validation

import io.csaf.schema.generated.Csaf
import kotlin.io.path.Path
import kotlin.io.path.readText
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/**
 * Represents a test as described in
 * [Section 6](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6-tests). They all
 * target a CSAF document, represented by the [Csaf] type.
 */
interface Test {

    /**
     * Validates a [Csaf] document object to the CSAF 2.0 standard.
     *
     * Note: This will NOT contain any validation errors that occur because of JSON schema
     * validation, since these will already be checked by the constructor of the [Csaf] object, so
     * it is impossible to create a [Csaf] document that violates the JSON schema (unless done by
     * black reflection magic).
     */
    fun test(doc: Csaf): ValidationResult

    /**
     * Validates a JSON file given in the [path] to the CSAF 2.0 standard.
     *
     * Note: This will also wrap any [SerializationException] that might occur because of JSON
     * schema validations into the [ValidationResult].
     */
    fun test(path: String): ValidationResult {
        try {
            val doc = Json.decodeFromString<Csaf>(Path(path).readText())
            return this.test(doc)
        } catch (ex: SerializationException) {
            return ex.toValidationResult()
        }
    }
}
