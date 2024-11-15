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
package io.github.csaf.sbom.retrieval.requirements

import io.github.csaf.sbom.retrieval.RetrievalContext
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationResult
import io.github.csaf.sbom.validation.ValidationSuccessful
import kotlin.test.Test
import kotlin.test.assertIs

class TestRetrievalContext : RetrievalContext()

val alwaysFail =
    object : Requirement {
        override fun check(ctx: RetrievalContext): ValidationResult {
            return ValidationFailed()
        }
    }

val alwaysGood =
    object : Requirement {
        override fun check(ctx: RetrievalContext): ValidationResult {
            return ValidationSuccessful
        }
    }

class RequirementTest {
    @Test
    fun testCheck() {
        val requirement = alwaysGood
        val result = requirement.check(TestRetrievalContext())
        assertIs<ValidationSuccessful>(result)
    }

    @Test
    fun testAnd() {
        val requirement = alwaysFail + alwaysGood
        val result = requirement.check(TestRetrievalContext())
        assertIs<ValidationFailed>(result)
    }

    @Test
    fun testOr() {
        val requirement = alwaysFail or alwaysGood
        val result = requirement.check(TestRetrievalContext())
        assertIs<ValidationSuccessful>(result)
    }

    @Test
    fun testAllOf() {
        val requirement = allOf(alwaysFail, alwaysGood, alwaysGood, alwaysFail)
        val result = requirement.check(TestRetrievalContext())
        assertIs<ValidationFailed>(result)
    }

    @Test
    fun testOneOf() {
        val requirement = oneOf(alwaysFail, alwaysGood, alwaysGood, alwaysFail)
        val result = requirement.check(TestRetrievalContext())
        assertIs<ValidationSuccessful>(result)

        val failingRequirement = oneOf(alwaysFail, alwaysFail, alwaysFail)
        val failingResult = failingRequirement.check(TestRetrievalContext())
        assertIs<ValidationFailed>(failingResult)
    }
}
