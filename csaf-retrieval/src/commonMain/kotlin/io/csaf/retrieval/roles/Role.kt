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
package io.csaf.retrieval.roles

import io.csaf.retrieval.RetrievalContext
import io.csaf.retrieval.requirements.Requirement
import io.csaf.validation.ValidationResult

/**
 * Represents a CSAF profile according to
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#72-roles.
 */
interface Role {

    /**
     * The list of requirements, that this role needs to fulfill on its own metadata according to
     * the standard. This can either be a single [io.csaf.retrieval.requirements.Requirement] or a
     * combination thereof using the operators [io.csaf.retrieval.requirements.allOf].
     * [io.csaf.retrieval.requirements.oneOf], [io.csaf.retrieval.requirements.or].
     */
    val roleRequirements: Requirement

    /**
     * The list of requirements, that this role needs to fulfill for each CSAF document according to
     * the standard. This can either be a single [Requirement] or a combination thereof using the
     * operators [io.csaf.retrieval.requirements.allOf]. [io.csaf.retrieval.requirements.oneOf],
     * [io.csaf.retrieval.requirements.or].
     */
    val documentRequirements: Requirement

    fun checkRole(ctx: RetrievalContext): ValidationResult {
        return roleRequirements.check(ctx)
    }

    fun checkDocument(ctx: RetrievalContext): ValidationResult {
        return documentRequirements.check(ctx)
    }
}
