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
package io.github.csaf.validation.roles

import io.github.csaf.validation.TestValidationContext
import io.github.csaf.validation.ValidationSuccessful
import kotlin.test.Test
import kotlin.test.assertIs

class TestRoles {
    @Test
    fun testTrustedProvider() {
        val role = CSAFTrustedProviderRole()
        // TODO: adjust this, once we actually check something in the requirements
        //  for now this will fail
        val result = role.requirements.check(TestValidationContext())
        assertIs<ValidationSuccessful>(result)
    }

    @Test
    fun testAggregatorRole() {
        val role = CSAFAggregatorRole()
        // TODO: adjust this, once we actually check something in the requirements
        //  for now all will succeed
        val result = role.requirements.check(TestValidationContext())
        assertIs<ValidationSuccessful>(result)
    }
}
