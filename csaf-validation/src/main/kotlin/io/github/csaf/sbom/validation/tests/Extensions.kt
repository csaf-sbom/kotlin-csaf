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

fun Csaf.ProductTree?.gatherProductGroupsTo(groups: MutableCollection<Csaf.ProductGroup>) {
    if (this == null) return

    groups += this.product_groups
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

fun Csaf.gatherProductReferences(): MutableCollection<String> {
    val ids = mutableSetOf<String>()

    product_tree.gatherProductReferencesTo(ids)
    vulnerabilities.gatherProductReferencesTo(ids)

    return ids
}

fun Csaf.gatherProductGroupReferences(): MutableCollection<String> {
    val ids = mutableSetOf<String>()

    vulnerabilities.gatherProductGroupReferencesTo(ids)

    return ids
}

fun Csaf.ProductTree?.gatherProductReferencesTo(ids: MutableCollection<String>) {
    if (this == null) return

    product_groups.gatherProductReferencesTo(ids)
    relationships.gatherProductReferencesTo(ids)
    relationships.gatherProductReferencesTo(ids)
}

fun Csaf.Vulnerability.gatherProductReferencesTo(ids: MutableCollection<String>) {
    product_status.gatherProductReferencesTo(ids)
    remediations.gatherProductReferencesTo(ids)
    scores.gatherProductReferencesTo(ids)
    threats.gatherProductReferencesTo(ids)
}

fun Csaf.Vulnerability.gatherProductGroupReferencesTo(ids: MutableCollection<String>) {
    remediations.gatherProductGroupReferencesTo(ids)
    threats.gatherProductGroupReferencesTo(ids)
}

fun Csaf.ProductStatus?.gatherProductReferencesTo(ids: MutableCollection<String>) {
    gatherAffectedProductReferencesTo(ids)
    gatherNotAffectedProductReferencesTo(ids)
    gatherFixedProductReferencesTo(ids)
    gatherUnderInvestigationProductReferencesTo(ids)
    gatherRecommendedProductReferencesTo(ids)
}

fun Csaf.ProductStatus?.gatherAffectedProductReferencesTo(ids: MutableCollection<String>) {
    if (this == null) return

    ids += first_affected
    ids += known_affected
    ids += last_affected
}

fun Csaf.ProductStatus?.gatherNotAffectedProductReferencesTo(ids: MutableCollection<String>) {
    if (this == null) return

    ids += known_not_affected
}

fun Csaf.ProductStatus?.gatherFixedProductReferencesTo(ids: MutableCollection<String>) {
    if (this == null) return

    ids += first_fixed
    ids += fixed
}

fun Csaf.ProductStatus?.gatherUnderInvestigationProductReferencesTo(
    ids: MutableCollection<String>
) {
    if (this == null) return

    ids += under_investigation
}

fun Csaf.ProductStatus?.gatherRecommendedProductReferencesTo(ids: MutableCollection<String>) {
    if (this == null) return

    ids += recommended
}

fun List<*>?.gatherProductReferencesTo(ids: MutableCollection<String>) {
    if (this == null) return

    for (e in this) {
        when (e) {
            is Csaf.Vulnerability -> e.gatherProductReferencesTo(ids)
            is Csaf.ProductGroup -> ids += e.product_ids
            is Csaf.Relationship -> {
                ids += e.product_reference
                ids += e.relates_to_product_reference
            }
            is Csaf.Remediation -> ids += e.product_ids
            is Csaf.Score -> ids += e.products
            is Csaf.Threat -> ids += e.product_ids
        }
    }
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
