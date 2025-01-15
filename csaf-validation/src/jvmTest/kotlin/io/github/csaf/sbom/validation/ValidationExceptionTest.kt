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

import kotlin.test.Test
import kotlin.test.assertEquals

class ValidationExceptionTest {
    @Test
    fun `Test for single error message`() {
        val validationException = ValidationException(listOf("Single error"))
        assertEquals(
            "Validation failed with this errors: [Single error]",
            validationException.message,
        )
    }

    @Test
    fun `Test for multiple error messages`() {
        val validationException = ValidationException(listOf("First error", "Second error"))
        assertEquals(
            "Validation failed with this errors: [First error, Second error]",
            validationException.message,
        )
    }

    @Test
    fun `Test for no error message`() {
        val validationException = ValidationException(emptyList())
        assertEquals("Validation failed with this errors: []", validationException.message)
    }
}
