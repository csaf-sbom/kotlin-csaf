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

fun allOf(vararg requirements: Requirement): Requirement {
    return AllOf(requirements.toList())
}

class AllOf(var list: List<Requirement>) : Requirement {
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

fun oneOf(vararg requirements: Requirement): Requirement {
    return OneOf(requirements.toList())
}

class OneOf(var list: List<Requirement>) : Requirement {
    override fun check(target: Any): ValidationResult {
        return if (list.map { check(target) }.any { it is ValidationSuccessful }) {
            ValidationSuccessful
        } else {
            // TODO: populate errors from list
            ValidationFailed(emptyList())
        }
    }
}

infix fun Requirement.or(other: Requirement): Requirement {
    return Or(this, other)
}

class Or(var lhs: Requirement, var rhs: Requirement) : Requirement {
    override fun check(target: Any): ValidationResult {
        var lhsResult = lhs.check(target)
        var rhsResult = rhs.check(target)
        return when {
            lhsResult is ValidationSuccessful && rhsResult is ValidationSuccessful -> {
                return ValidationSuccessful
            }
            lhsResult is ValidationFailed && rhsResult is ValidationFailed -> {
                return ValidationFailed(lhsResult.errors + rhsResult.errors)
            }
            lhsResult is ValidationFailed && rhsResult is ValidationSuccessful -> {
                return ValidationSuccessful
            }
            lhsResult is ValidationSuccessful && rhsResult is ValidationFailed -> {
                return ValidationSuccessful
            }
            else -> {
                throw RuntimeException("unreachable state reached")
            }
        }
    }
}

operator fun Requirement.plus(other: Requirement): Requirement {
    return And(this, other)
}

class And(var lhs: Requirement, var rhs: Requirement) : Requirement {
    override fun check(target: Any): ValidationResult {
        var lhsResult = lhs.check(target)
        var rhsResult = rhs.check(target)
        return when {
            lhsResult is ValidationSuccessful && rhsResult is ValidationSuccessful -> {
                return ValidationSuccessful
            }
            lhsResult is ValidationFailed && rhsResult is ValidationFailed -> {
                return ValidationFailed(lhsResult.errors + rhsResult.errors)
            }
            lhsResult is ValidationFailed && rhsResult is ValidationSuccessful -> {
                return lhsResult
            }
            lhsResult is ValidationSuccessful && rhsResult is ValidationFailed -> {
                return rhsResult
            }
            else -> {
                throw RuntimeException("unreachable state reached")
            }
        }
    }
}
