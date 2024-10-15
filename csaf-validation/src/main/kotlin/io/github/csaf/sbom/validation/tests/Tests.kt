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
package io.github.csaf.sbom.validation.tests

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.Test
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationResult
import io.github.csaf.sbom.validation.ValidationSuccessful

object Test611MissingDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definedProductIds =
            doc.product_tree?.full_product_names?.map { it.product_id }?.toSet() ?: setOf()

        // Gather all identifiers
        val ids = mutableSetOf<String>()
        ids += doc.product_tree?.product_groups?.flatMap { it.product_ids }
        ids += doc.product_tree?.relationships?.map { it.product_reference }
        ids += doc.product_tree?.relationships?.map { it.relates_to_product_reference }

        for (vuln in doc.vulnerabilities ?: listOf()) {
            vuln.product_status?.let { ids += it.first_affected }
        }

        val notDefined = ids.subtract(definedProductIds)

        return if (notDefined.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("invalid IDs: ${notDefined.joinToString(",")}"))
        }
    }
}

private operator fun <E> MutableSet<E>.plusAssign(set: Collection<E>?) {
    if (set != null) {
        this.addAll(set)
    }
}
