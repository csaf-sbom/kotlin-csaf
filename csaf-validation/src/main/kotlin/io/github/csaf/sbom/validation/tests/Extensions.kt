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
import io.github.csaf.sbom.validation.tests.plusAssign

private fun Csaf.Branche.gatherProductIds(): Set<String> {
    val ids = mutableSetOf<String>()

    // Add ID at this leaf
    product?.let { ids += it.product_id }

    // Go down the branch
    this.branches?.flatMapTo(ids) { it.gatherProductIds() }

    return ids
}

fun List<Csaf.Product>?.gatherProductIds(): Set<String> {
    return if (this == null) {
        setOf()
    } else {
        map { it.product_id }.toMutableSet()
    }
}

fun Csaf.ProductTree.gatherProductIds(): Set<String> {
    val ids = mutableSetOf<String>()

    ids += this.full_product_names.gatherProductIds()
    ids += this.branches?.flatMap { it.gatherProductIds() }?.toSet() ?: setOf()
    ids += this.relationships?.map { it.full_product_name.product_id } ?: setOf()

    return ids
}

fun Csaf.gatherProductReferences(): MutableSet<String> {
    val ids = mutableSetOf<String>()
    ids += product_tree?.product_groups?.flatMap { it.product_ids }
    ids += product_tree?.relationships?.map { it.product_reference }
    ids += product_tree?.relationships?.map { it.relates_to_product_reference }

    for (vuln in vulnerabilities ?: listOf()) {
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

private operator fun <E> MutableSet<E>.plusAssign(set: Collection<E>?) {
    if (set != null) {
        this.addAll(set)
    }
}
