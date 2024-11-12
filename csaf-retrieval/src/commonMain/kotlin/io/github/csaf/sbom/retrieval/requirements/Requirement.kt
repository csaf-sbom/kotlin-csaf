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

import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationResult
import io.github.csaf.sbom.validation.ValidationSuccessful
import io.github.csaf.sbom.validation.merge

/**
 * Represents a requirement that the CSAF standard defines in
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#71-requirements. Since
 * requirements are often re-used across different [Role]s, there are some helper functions to
 * combine requirements, such as [oneOf], [allOf] or [or].
 */
interface Requirement {
    fun check(ctx: io.github.csaf.sbom.retrieval.RetrievalContext): ValidationResult
}

private class NoRequirement : Requirement {
    override fun check(ctx: io.github.csaf.sbom.retrieval.RetrievalContext): ValidationResult {
        return ValidationSuccessful
    }
}

/** Creates a new [Requirement] that specifies that no requirements need to be fulfilled. */
fun none(): Requirement {
    return NoRequirement()
}

/**
 * Creates a new [Requirement] that specifies that all the requirements in [requirements] must be
 * fulfilled.
 *
 * @param requirements the requirements to be fulfilled.
 * @return a new combined [Requirement] that is fulfilled if all its sub-requirements are fulfilled.
 */
fun allOf(vararg requirements: Requirement): Requirement {
    return AllOf(requirements.toList())
}

private class AllOf(private val list: List<Requirement>) : Requirement {
    override fun check(ctx: io.github.csaf.sbom.retrieval.RetrievalContext): ValidationResult {
        val results = list.map { it.check(ctx) }
        return results.merge()
    }
}

/**
 * Creates a new [Requirement] that specifies that one the requirements in [requirements] must be
 * fulfilled.
 *
 * @param requirements the requirements to chose from.
 * @return a new combined [Requirement] that is fulfilled if one of its sub-requirements are
 *   fulfilled.
 */
fun oneOf(vararg requirements: Requirement): Requirement {
    return OneOf(requirements.toList())
}

private class OneOf(private val list: List<Requirement>) : Requirement {
    override fun check(ctx: io.github.csaf.sbom.retrieval.RetrievalContext): ValidationResult {
        val results = list.map { it.check(ctx) }
        return if (results.all { it is ValidationFailed }) {
            ValidationFailed(results.flatMap { (it as ValidationFailed).errors })
        } else {
            ValidationSuccessful
        }
    }
}

/**
 * Creates a new [Requirement] that specifies that either [this] or the [other] requirement must be
 * fulfilled.
 *
 * @param other the other requirements
 * @return a combined [Requirement] that is fulfilled if either this or the [other] requirement is
 *   fulfilled.
 */
infix fun Requirement.or(other: Requirement): Requirement {
    return OneOf(listOf(this, other))
}

/**
 * Creates a new [Requirement] that specifies that this [this] and the [other] requirement must be
 * fulfilled.
 *
 * @param other the other requirements
 * @return a combined [Requirement] that is fulfilled if this and the [other] is fulfilled.
 */
operator fun Requirement.plus(other: Requirement): Requirement {
    return AllOf(listOf(this, other))
}
