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

/** Result defines the result of a requirement check. It */
sealed interface ValidationResult

/** A successful validation. */
data object ValidationSuccessful : ValidationResult

// TODO(oxisto): Does it make sense to have something like NotApplicable? Currently, this does not
//  propagate
val ValidationNotApplicable = ValidationSuccessful

/**
 * A [ValidationResult] that represents a failed validation, with extra information why it failed.
 */
data class ValidationFailed(
    /** Any errors encountered during the validation. */
    val errors: List<String> = emptyList()
) : ValidationResult {
    fun toException() = ValidationException(errors)
}

/** Merges together the content of all [ValidationResult] objects in this list. */
fun List<ValidationResult>.merge(): ValidationResult {
    return if (any { it is ValidationFailed }) {
        ValidationFailed(
            flatMap {
                if (it is ValidationFailed) {
                    it.errors
                } else {
                    emptyList()
                }
            }
        )
    } else {
        ValidationSuccessful
    }
}
