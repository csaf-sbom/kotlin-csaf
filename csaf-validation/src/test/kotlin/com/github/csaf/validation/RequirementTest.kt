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
package com.github.csaf.validation

import kotlin.test.Test
import kotlin.test.assertIs

class RequirementTest {
    @Test
    fun testCheck() {
        class AlwaysTrue : Requirement() {
            override fun check(target: Any): ValidationResult {
                return ValidationSuccessful
            }
        }

        var requirement = AlwaysTrue()
        var result = requirement.check(Any())
        assertIs<ValidationSuccessful>(result)
    }
}
