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
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

interface MatchingConfidence {
    val value: Float
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
class PurlMatchingTask(val purl: Purl) : MatchingTask {

    override fun match(component: Node): MatchingConfidence {
        // Check, if we have a purl to match against
        val componentPurl =
            component.identifiers[SoftwareIdentifierType.PURL.value]?.let { Purl(it) }
        if (componentPurl == null) {
            return MatcherNotSuitable
        }

        return purl.confidenceMatching(componentPurl)
    }
}
