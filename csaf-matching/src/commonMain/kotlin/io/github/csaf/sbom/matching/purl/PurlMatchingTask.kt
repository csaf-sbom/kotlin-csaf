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
package io.github.csaf.sbom.matching.purl

import io.github.csaf.sbom.matching.MatchingTask
import io.github.csaf.sbom.matching.ProductInfo
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

interface MatchingConfidence {
    val value: Float

    operator fun plus(other: MatchingConfidence): MatchingConfidence {
        return when (this) {
            is DefiniteMatch -> other
            is DefinitelyNoMatch -> this
            else -> CombinedMatch(listOf(this, other))
        }
    }
}

class CombinedMatch(elements: List<MatchingConfidence>) : MatchingConfidence {
    override val value = elements.map { it.value }.reduce { acc, element -> acc * element }
}

/** A [DefiniteMatch] indicates a definite match. This is the highest possible match value. */
object DefiniteMatch : MatchingConfidence {
    override val value = 1.0f
}

/** A [DefinitelyNoMatch] indicates a definite no match. This is the lowest possible match value. */
object DefinitelyNoMatch : MatchingConfidence {
    override val value = 0.0f
}

/**
 * A [PartialNameMatch] indicates that the name of the vulnerable product partially matches the
 * affected component.
 */
object PartialNameMatch : MatchingConfidence {
    override val value = 0.5f
}

/**
 * A [MatchPackageNoVersion] indicates a match, but the version is not set. This is a partial match
 * because we consider that semantically means that the package is affected, but we do not know
 * which version. So in theory, all versions that are in the SBOM could be a match. It is not a
 * definite match, but it is also not a no match. It is a partial match.
 */
object MatchPackageNoVersion : MatchingConfidence {
    override val value = 0.7f
}

/** A [MatcherNotSuitable] indicates that the matcher is not suitable for the given component. */
object MatcherNotSuitable : MatchingConfidence {
    override val value = -1.0f
}

fun Purl.confidenceMatching(other: Purl): MatchingConfidence {
    // All of these must match, otherwise we definitely not have a match. We can skip comparing the
    // scheme because the schema is already checked in the Purl constructor.
    if (this.getType() != other.getType()) return DefinitelyNoMatch
    if (this.getNamespace() != other.getNamespace()) return DefinitelyNoMatch
    if (this.getName() != other.getName()) return DefinitelyNoMatch

    // If the version is not set, we have a match, but we are not completely sure. It could either
    // mean that someone forgot to set the version or that that all versions are affected.
    if (this.getVersion() == null) return MatchPackageNoVersion

    // If the version is set, we have a match if the versions are equal
    if (this.getVersion() == other.getVersion()) return DefiniteMatch

    return DefinitelyNoMatch
}

/**
 * A [PurlMatchingTask] is a matching task that matches a PURL (specified in the security advisory)
 * against a component. It implements the [MatchingTask] interface.
 *
 * It uses the [Purl.confidenceMatching] function to determine the matching confidence.
 */
object PurlMatchingTask : MatchingTask {

    override fun match(vulnerable: ProductInfo, component: Node): MatchingConfidence {
        // Check if we have a purl in the vulnerable product
        val vulnerablePurl = vulnerable.purl

        // Check, if we have a purl to match against
        val componentPurl =
            component.identifiers[SoftwareIdentifierType.PURL.value]?.let { Purl(it) }

        // No purl in the vulnerable product or no purl in the component means we cannot match with
        // this matcher (for now).
        if (vulnerablePurl == null || componentPurl == null) {
            return MatcherNotSuitable
        }

        return vulnerablePurl.confidenceMatching(componentPurl)
    }
}
