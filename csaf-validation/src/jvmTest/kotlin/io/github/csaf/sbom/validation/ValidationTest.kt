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
package io.github.csaf.sbom.validation

import kotlin.test.*

/**
 * Asserts that the [result] is a [ValidationFailed] result and that the [ValidationFailed.errors]
 * is equal to the [message].
 */
fun assertValidationFailed(message: String, result: ValidationResult) {
    return assertEquals(ValidationFailed(listOf(message)), result)
}

/** Asserts that the [result] is a [ValidationSuccessful] result. */
fun assertValidationSuccessful(result: ValidationResult) {
    return assertEquals(ValidationSuccessful, result)
}
