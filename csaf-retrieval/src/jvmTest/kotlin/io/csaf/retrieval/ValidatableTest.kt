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
package io.csaf.retrieval

import io.csaf.retrieval.roles.Role
import io.csaf.validation.ValidationException
import io.csaf.validation.ValidationFailed
import io.csaf.validation.ValidationSuccessful
import io.mockk.every
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertFailsWith

class ValidatableTest {

    class TestValidatable(override val role: Role) : Validatable

    @Test
    fun `validate should not throw an exception if role validation passes`() {
        val mockRole = mockk<Role>()
        val retrievalContext = RetrievalContext()

        every { mockRole.checkRole(retrievalContext) } returns ValidationSuccessful

        val validatable = TestValidatable(mockRole)
        validatable.validate(retrievalContext)
    }

    @Test
    fun `validate should throw ValidationFailed exception if role validation fails`() {
        val mockRole = mockk<Role>()
        val retrievalContext = RetrievalContext()
        val validationFailed = ValidationFailed(listOf("Validation Error"))

        every { mockRole.checkRole(retrievalContext) } returns validationFailed

        val validatable = TestValidatable(mockRole)
        assertFailsWith<ValidationException> { validatable.validate(retrievalContext) }
    }
}
