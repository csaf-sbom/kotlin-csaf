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
package com.github.csaf.validation.standards.csaf20

import com.github.csaf.validation.Requirement
import com.github.csaf.validation.ValidationFailed
import com.github.csaf.validation.ValidationResult
import com.github.csaf.validation.ValidationSuccessful

/**
 * Represents Requirement 1: Valid CSAF document.
 *
 * See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#711-requirement-1-valid-csaf-document
 */
class ValidCSAFDocument : Requirement() {
    override fun check(target: Any): ValidationResult {
        // TOOD: actually implement the requirement
        return ValidationSuccessful
    }
}

/**
 * Represents Requirement 1: Valid CSAF document.
 *
 * See https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#712-requirement-2-filename
 */
class ValidFilename : Requirement() {
    override fun check(target: Any): ValidationResult {
        // TOOD: actually implement the requirement
        return ValidationFailed(errors = listOf("very bad error"))
    }
}
