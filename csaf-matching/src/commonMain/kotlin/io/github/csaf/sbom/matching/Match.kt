/*
 * Copyright (c) 2025, The Authors. All rights reserved.
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
package io.github.csaf.sbom.matching

import io.github.csaf.sbom.matching.properties.PropertySource
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Product
import io.github.csaf.sbom.validation.tests.plusAssign
import protobom.protobom.Node

/**
 * A utility class for a [Product] and a list of [Csaf.Branche]s that define the "path" from the
 * roof of the [Csaf.ProductTree] to the [Product]
 */
data class VulnerableProduct(var product: Product, var branches: List<Csaf.Branche>) {
    val cpe: Cpe? = product.product_identification_helper?.cpe?.let { parseCpe(it) }
    val purl: Purl? = product.product_identification_helper?.purl?.let { Purl(it.toString()) }
}

fun Csaf.ProductTree?.gatherVulnerableProducts(
    predicate: ((Product) -> Boolean)? = null
): List<VulnerableProduct> {
    val products = mutableListOf<VulnerableProduct>()
    val worklist = mutableListOf<List<Csaf.Branche>>()
    val alreadySeen = mutableSetOf<Csaf.Branche>()

    // Start with this branches
    worklist += this?.branches

    while (worklist.isNotEmpty()) {
        val currentPath = worklist.maxBy { it.size }
        worklist.remove(currentPath)

        val currentBranch = currentPath.last()
        alreadySeen += currentBranch

        val nextBranches = currentBranch.branches
        for (nextBranch in nextBranches ?: listOf()) {
            // We arrived at a product node, we are finished
            val product = nextBranch.product
            if (product != null && predicate?.invoke(product) != false) {
                val vulnerableProduct =
                    VulnerableProduct(product = product, branches = currentPath + nextBranch)
                products.add(vulnerableProduct)
                // Done with this path
                continue
            }

            // Otherwise, continue
            worklist.add(currentPath + nextBranch)
        }
    }

    return products
}

interface MatchingConfidence {
    val value: Float

    operator fun times(other: MatchingConfidence): MatchingConfidence {
        return when {
            this is DefiniteMatch -> other
            this is DefinitelyNoMatch -> this
            other is DefiniteMatch -> this
            other is DefinitelyNoMatch -> other
            else -> CombinedMatch(listOf(this, other))
        }
    }
}

/**
 * A [CombinedMatch] indicates a match that is combined from multiple [elements] with different
 * confidence.
 *
 * The value of a [CombinedMatch] is the product of the values of the [MatchingConfidence] elements.
 */
data class CombinedMatch(val elements: List<MatchingConfidence>) : MatchingConfidence {
    override val value = elements.map { it.value }.reduce { acc, element -> acc * element }
}

/**
 * A [DefiniteMatch] indicates a definite match. This is the highest possible match value. This
 * should be used if two properties match exactly -- either lexically or by rules defined in a
 * specification. For example if one [Cpe] matches another, this is a [DefiniteMatch].
 */
data object DefiniteMatch : MatchingConfidence {
    override val value = 1.0f
}

/**
 * A [CaseInsensitiveMatch] indicates a (string-based) match that is case-insensitive. This is a
 * high match value, but not as high as a [DefiniteMatch].
 */
data object CaseInsensitiveMatch : MatchingConfidence {
    override val value = 0.95f
}

/**
 * A [CaseInsensitiveIgnoreDashMatch] indicates a (string-based) match that is case-insensitive and
 * ignores dashes. This is a relatively high match value, but not as high as a
 * [CaseInsensitiveMatch].
 */
data object CaseInsensitiveIgnoreDashMatch : MatchingConfidence {
    override val value = 0.90f
}

/**
 * A [PartialStringMatch] indicates that a string property of the vulnerable product partially
 * matches the affected component's string property.
 */
data object PartialStringMatch : MatchingConfidence {
    override val value = 0.5f
}

/**
 * A [DifferentSources] indicates that the information comes from different sources (e.g., matching
 * a [Cpe.getVendor] to a vendor specified in a [Csaf.Branche]. This can be used to "multiply" the
 * matching confidence with this value to adjust it for the different sources.
 */
data class DifferentSources(val sources: List<PropertySource>) : MatchingConfidence {
    override val value = 0.9f
}

/** A [DefinitelyNoMatch] indicates a definite no match. This is the lowest possible match value. */
data object DefinitelyNoMatch : MatchingConfidence {
    override val value = 0.0f
}

/**
 * A [MatchPackageNoVersion] indicates a match, but the version is not set. This is a partial match
 * because we consider that semantically means that the package is affected, but we do not know
 * which version. So in theory, all versions that are in the SBOM could be a match. It is not a
 * definite match, but it is also not a no match. It is a partial match.
 */
data object MatchPackageNoVersion : MatchingConfidence {
    override val value = 0.7f
}

/** A [MatcherNotSuitable] indicates that the matcher is not suitable for the given component. */
data object MatcherNotSuitable : MatchingConfidence {
    override val value = -1.0f
}

/**
 * A data class representing a match between an [Csaf.Product] to a SBOM [Node] with given
 * [MatchingConfidence].
 *
 * @property csaf The matched CSAF document.
 * @property vulnerableProduct The vulnerable product from the CSAF document.
 * @property affectedComponent The affected component from the SBOM document.
 * @property confidence The confidence score of the match.
 * @constructor Creates CSAF-SBOM-match with given score.
 */
data class Match(
    val csaf: Csaf,
    val vulnerableProduct: VulnerableProduct,
    val affectedComponent: Node,
    val confidence: MatchingConfidence,
)
