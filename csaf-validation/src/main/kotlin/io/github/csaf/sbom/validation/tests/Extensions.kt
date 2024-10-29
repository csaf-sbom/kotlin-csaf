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
import io.github.csaf.sbom.schema.generated.Csaf.Product

/**
 * Gathers product definitions at a [Csaf.Branche]. This is needed because we need to do it
 * recursively.
 */
fun Csaf.Branche.gatherProductDefinitionsTo(products: MutableCollection<String>) {
    // Add ID at this leaf
    products += product?.product_id

    // Go down the branch
    this.branches?.forEach { it.gatherProductDefinitionsTo(products) }
}

/** Gathers all [Product.product_id] definitions in the current document. */
fun Csaf.gatherProductDefinitions(): List<String> {
    val ids = mutableListOf<String>()

    // /product_tree/branches[](/branches[])*/product/product_id
    ids +=
        this.product_tree?.branches?.flatMap {
            var inner = mutableListOf<String>()
            it.gatherProductDefinitionsTo(inner)
            inner
        }

    // /product_tree/full_product_names[]/product_id
    ids += this.product_tree?.full_product_names?.map { it.product_id }

    // /product_tree/relationships[]/full_product_name/product_id
    ids += this.product_tree?.relationships?.map { it.full_product_name.product_id }

    return ids
}

/** Gathers all product IDs in the current document. */
fun Csaf.gatherProductReferences(): Set<String> {
    val ids = mutableSetOf<String>()

    // /product_tree/product_groups[]/product_ids[]
    ids += product_tree?.product_groups?.flatMap { it.product_ids }

    // /product_tree/relationships[]/product_reference
    // /product_tree/relationships[]/relates_to_product_reference
    ids +=
        product_tree?.relationships?.flatMap {
            listOf(it.product_reference, it.relates_to_product_reference)
        }

    // /vulnerabilities[]/product_status/first_affected[]
    // /vulnerabilities[]/product_status/first_fixed[]
    // /vulnerabilities[]/product_status/fixed[]
    // /vulnerabilities[]/product_status/known_affected[]
    // /vulnerabilities[]/product_status/known_not_affected[]
    // /vulnerabilities[]/product_status/last_affected[]
    // /vulnerabilities[]/product_status/recommended[]
    // /vulnerabilities[]/product_status/under_investigation[]
    // /vulnerabilities[]/remediations[]/product_ids[]
    // /vulnerabilities[]/scores[]/products[]
    // /vulnerabilities[]/threats[]/product_ids[]
    ids +=
        vulnerabilities?.flatMap {
            var inner = mutableSetOf<String>()
            inner += it.product_status?.first_affected
            inner += it.product_status?.first_fixed
            inner += it.product_status?.fixed
            inner += it.product_status?.known_affected
            inner += it.product_status?.known_not_affected
            inner += it.product_status?.last_affected
            inner += it.product_status?.recommended
            inner += it.product_status?.under_investigation
            inner += it.remediations?.flatMap { it.product_ids ?: emptySet() }
            inner += it.scores?.flatMap { it.products }
            inner += it.threats?.flatMap { it.product_ids ?: emptySet() }
            inner
        }

    return ids
}

/**
 * Gathers all [Product] definitions in the current document.
 *
 * Note: We could optimize this further by only retrieving the ID, but it might not hurt to have
 * access to the complete [Product].
 */
fun Csaf.gatherProductGroups(): Set<Csaf.ProductGroup> {
    val groups = mutableSetOf<Csaf.ProductGroup>()

    this.product_tree.gatherProductGroupsTo(groups)

    return groups
}

fun Csaf.ProductTree?.gatherProductGroupsTo(groups: MutableCollection<Csaf.ProductGroup>) {
    if (this == null) return

    groups += this.product_groups
}

fun Csaf.gatherProductGroupReferences(): MutableCollection<String> {
    val ids = mutableSetOf<String>()

    vulnerabilities.gatherProductGroupReferencesTo(ids)

    return ids
}

fun Csaf.Vulnerability.gatherProductGroupReferencesTo(ids: MutableCollection<String>) {
    remediations.gatherProductGroupReferencesTo(ids)
    threats.gatherProductGroupReferencesTo(ids)
}

fun List<*>?.gatherProductGroupReferencesTo(ids: MutableCollection<String>) {
    if (this == null) return

    for (e in this) {
        when (e) {
            is Csaf.Vulnerability -> e.gatherProductGroupReferencesTo(ids)
            is Csaf.Threat -> ids += e.group_ids
            is Csaf.Remediation -> ids += e.group_ids
        }
    }
}

internal operator fun <E> MutableCollection<E>.plusAssign(set: Collection<E>?) {
    if (set != null) {
        this.addAll(set)
    }
}

internal operator fun <E> MutableCollection<E>.plusAssign(item: E?) {
    if (item != null) {
        this.add(item)
    }
}

internal operator fun <E> Collection<E>?.plus(other: Collection<E>?): Collection<E> {
    return if (other != null && this != null) {
        this.union(other)
    } else if (other != null) {
        other
    } else if (this != null) {
        this
    } else {
        listOf()
    }
}
