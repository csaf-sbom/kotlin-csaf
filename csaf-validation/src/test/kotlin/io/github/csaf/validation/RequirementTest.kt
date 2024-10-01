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
package io.github.csaf.validation

import kotlin.test.Test
import kotlin.test.assertIs

class TestDocument : Validatable<Any> {
    override val json = Any()
}

class TestValidationContext(validatable: TestDocument = TestDocument()) :
    ValidationContext<Any, TestDocument>(validatable) {
    init {
        dataSource = DataSource.WELL_KNOWN
    }
}

val alwaysFail =
    object : Requirement {
        override fun check(ctx: ValidationContext<*, *>): ValidationResult {
            return ValidationFailed()
        }
    }

val alwaysGood =
    object : Requirement {
        override fun check(ctx: ValidationContext<*, *>): ValidationResult {
            return ValidationSuccessful
        }
    }

class RequirementTest {
    @Test
    fun testCheck() {
        val requirement = alwaysGood
        val result = requirement.check(TestValidationContext())
        assertIs<ValidationSuccessful>(result)
    }

    @Test
    fun testAnd() {
        val requirement = alwaysFail + alwaysGood
        val result = requirement.check(TestValidationContext())
        assertIs<ValidationFailed>(result)
    }

    @Test
    fun testOr() {
        val requirement = alwaysFail or alwaysGood
        val result = requirement.check(TestValidationContext())
        assertIs<ValidationSuccessful>(result)
    }

    @Test
    fun testAllOf() {
        val requirement = allOf(alwaysFail, alwaysGood, alwaysGood, alwaysFail)
        val result = requirement.check(TestValidationContext())
        assertIs<ValidationFailed>(result)
    }

    @Test
    fun testOneOf() {
        val requirement = oneOf(alwaysFail, alwaysGood, alwaysGood, alwaysFail)
        val result = requirement.check(TestValidationContext())
        assertIs<ValidationSuccessful>(result)
    }
}
