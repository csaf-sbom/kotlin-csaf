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
import io.github.csaf.sbom.validation.profiles.CSAFBase
import io.github.csaf.sbom.validation.profiles.Profile
import io.github.csaf.sbom.validation.profiles.officialProfiles

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
            val inner = mutableListOf<String>()
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
 * Gathers product URLs at a [Csaf.Branche]. This is needed because we need to do it recursively.
 */
fun Csaf.Branche.gatherProductURLs(products: MutableCollection<String>) {
    // Add ID at this leaf
    products += product?.product_identification_helper?.purl?.toString()

    // Go down the branch
    this.branches?.forEach { it.gatherProductURLs(products) }
}

/** Gathers all [Csaf.ProductIdentificationHelper.purl] definitions in the current document. */
fun Csaf.gatherProductURLs(): MutableList<String> {
    val purls = mutableListOf<String>()

    // /product_tree/branches[](/branches[])*/product/product_identification_helper/purl
    purls +=
        this.product_tree?.branches?.flatMap {
            var inner = mutableListOf<String>()
            it.gatherProductURLs(inner)
            inner
        }

    // /product_tree/full_product_names[]/product_identification_helper/purl
    purls +=
        this.product_tree?.full_product_names?.mapNotNull {
            it.product_identification_helper?.purl?.toString()
        }

    // /product_tree/relationships[]/full_product_name/product_identification_helper/purl
    purls +=
        this.product_tree?.relationships?.mapNotNull {
            it.full_product_name.product_identification_helper?.purl?.toString()
        }

    return purls
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
            val inner = mutableSetOf<String>()
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
 * Gathers all [Csaf.ProductGroup.product_ids] definitions in the current document and groups them
 * into a map with their [Csaf.ProductGroup.group_id]. This is needed because sometimes references
 * such as [Csaf.Remediation] target a group instead of individual products, and we need to
 * "resolve" the group ID to their product IDs.
 */
fun Csaf.gatherProductIdsPerGroup(): Map<String, Set<String>> {
    return this.product_tree?.product_groups?.associateBy({ it.group_id }, { it.product_ids })
        ?: mapOf()
}

/** Gathers all [Csaf.ProductGroup.group_id] definitions in the current document. */
fun Csaf.gatherProductGroups(): List<String> {
    val groups = mutableListOf<String>()

    // /product_tree/product_groups[]/group_id
    groups += product_tree?.product_groups?.map { it.group_id }

    return groups
}

/** Gather all group ID references in the current document. */
fun Csaf.gatherProductGroupReferences(): Set<String> {
    val ids = mutableSetOf<String>()

    // /vulnerabilities[]/remediations[]/group_ids
    // /vulnerabilities[]/threats[]/group_ids
    ids +=
        vulnerabilities?.flatMap {
            val inner = mutableSetOf<String>()
            inner += it.remediations?.flatMap { it.group_ids ?: setOf() }
            inner += it.threats?.flatMap { it.group_ids ?: setOf() }
            inner
        }

    return ids
}

fun Csaf.Branche.gatherFileHashLists(lists: MutableCollection<List<Csaf.FileHashe>>) {
    // Add file hashes at this leaf
    lists += this.product?.product_identification_helper?.hashes?.map { it.file_hashes }

    // Go down the branch
    this.branches?.forEach { it.gatherFileHashLists(lists) }
}

fun Csaf.gatherFileHashLists(): MutableList<List<Csaf.FileHashe>> {
    var lists = mutableListOf<List<Csaf.FileHashe>>()

    // /product_tree/branches[](/branches[])*/product/product_identification_helper/hashes[]/file_hashes
    this.product_tree?.branches?.forEach { it.gatherFileHashLists(lists) }

    // /product_tree/full_product_names[]/product_identification_helper/hashes[]/file_hashes
    lists +=
        this.product_tree?.full_product_names?.flatMap {
            it.product_identification_helper?.hashes?.map { it.file_hashes } ?: listOf()
        }

    // /product_tree/relationships[]/full_product_name/product_identification_helper/hashes[]/file_hashes
    lists +=
        this.product_tree?.relationships?.flatMap {
            it.full_product_name.product_identification_helper?.hashes?.map { it.file_hashes }
                ?: listOf()
        }

    return lists
}

/**
 * Returns the profile according to
 * [Section 4](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#4-profiles). If this
 * is a local profile, [CSAFBase] is returned as a "catch-all".
 */
val Csaf.profile: Profile?
    get() {
        return officialProfiles[this.document.category] ?: CSAFBase
    }

internal fun Collection<String>?.resolveProductIDs(
    map: Map<String, Collection<String>>
): Collection<String>? {
    return this?.flatMap { map[it] ?: setOf() }
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
        // We return a set here, to stay consistent with "union"
        setOf()
    }
}

internal operator fun <E> Collection<E>?.minus(other: Collection<E>?): Collection<E> {
    return if (other != null && this != null) {
        this.subtract(other)
    } else if (other != null) {
        setOf()
    } else if (this != null) {
        this
    } else {
        // We return a set here, to stay consistent with "union"
        setOf()
    }
}
