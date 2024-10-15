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
        val definitions = doc.product_tree?.gatherProductIds() ?: setOf()
        val references = gatherProductReferences(doc)

        val notDefined = references.subtract(definitions)

        return if (notDefined.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are not defined: ${notDefined.joinToString(",")}")
            )
        }
    }
}

object Test621UnusedDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.product_tree?.gatherProductIds() ?: setOf()
        val references = gatherProductReferences(doc)

        val notUsed = definitions.subtract(references)
        return if (notUsed.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The following IDs are not used: ${notUsed.joinToString(",")}"))
        }
    }
}

private fun Csaf.Branche.gatherProductIds(): Set<String> {
    val ids = mutableSetOf<String>()

    // Add ID at this leaf
    product?.let { ids += it.product_id }

    // Go down the branch
    this.branches?.flatMapTo(ids) { it.gatherProductIds() }

    return ids
}

private operator fun <E> MutableSet<E>.plusAssign(set: Collection<E>?) {
    if (set != null) {
        this.addAll(set)
    }
}

private fun Csaf.ProductTree.gatherProductIds(): Set<String> {
    val ids = mutableSetOf<String>()

    ids += this.full_product_names?.map { it.product_id }?.toMutableSet() ?: mutableSetOf()
    ids += this.branches?.flatMap { it.gatherProductIds() }?.toSet() ?: setOf()
    ids += this.relationships?.map { it.full_product_name.product_id } ?: setOf()

    return ids
}

private fun gatherProductReferences(doc: Csaf): MutableSet<String> {
    val ids = mutableSetOf<String>()
    ids += doc.product_tree?.product_groups?.flatMap { it.product_ids }
    ids += doc.product_tree?.relationships?.map { it.product_reference }
    ids += doc.product_tree?.relationships?.map { it.relates_to_product_reference }

    for (vuln in doc.vulnerabilities ?: listOf()) {
        vuln.product_status?.let {
            ids += it.first_affected
            ids += it.first_fixed
            ids += it.fixed
            ids += it.known_affected
            ids += it.known_not_affected
            ids += it.last_affected
            ids += it.recommended
            ids += it.under_investigation
        }

        ids += vuln.remediations?.flatMap { it.product_ids ?: setOf() }
        ids += vuln.scores?.flatMap { it.products }
        ids += vuln.threats?.flatMap { it.product_ids ?: setOf() }
    }
    return ids
}
