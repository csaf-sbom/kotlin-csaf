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

/** Represents a requirement that the CSAF standard defines in */
interface Requirement {
    fun check(target: Any): ValidationResult
}

sealed class LogicalRequirementCombination : Requirement {}

class AllOf(var list: List<Requirement>) : LogicalRequirementCombination() {
    override fun check(target: Any): ValidationResult {
        var result: ValidationResult = ValidationSuccessful
        for (requirement in list) {
            var tmpResult = requirement.check(target)
            if (tmpResult is ValidationFailed) {
                // TODO: accumulate errors instead of last one
                result = ValidationFailed(tmpResult.errors)
            }
        }

        return result
    }
}

fun allOf(vararg requirements: Requirement): Requirement {
    return AllOf(requirements.toList())
}
