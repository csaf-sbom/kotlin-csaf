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

import io.github.csaf.sbom.matching.purl.DefiniteMatch
import io.github.csaf.sbom.matching.purl.DefinitelyNoMatch
import io.github.csaf.sbom.matching.purl.MatchPackageNoVersion
import io.github.csaf.sbom.matching.purl.MatchingConfidence
import io.github.csaf.sbom.matching.purl.PartialNameMatch
import io.github.csaf.sbom.schema.generated.Csaf
import protobom.protobom.Node

/**
 * A [BranchMatchingTask] is a [MatchingTask] that matches a [ProductInfo] against a [Node] based on
 * the information contained in [Csaf.Branche].
 */
object BranchMatchingTask : MatchingTask {
    override fun match(vulnerable: ProductInfo, component: Node): MatchingConfidence {
        // First, try to match the name. If we have a definite mismatch we can exit early
        var match: MatchingConfidence = vulnerable.matchesName(component)
        if (match == DefinitelyNoMatch) {
            return DefinitelyNoMatch
        }

        // Then, try to match the version. If we have a definite mismatch we can exit early
        match += vulnerable.matchesVersion(component)
        if (match == DefinitelyNoMatch) {
            return DefinitelyNoMatch
        }

        return match
    }
}

fun ProductInfo.matchesVersion(node: Node): MatchingConfidence {
    val vulnerableVersion =
        this.branches.find { it.category == Csaf.Category3.product_version }?.name
    val componentVersion = node.version

    // In an effort to sanitize the version strings, we remove training zeros and leading 'v'
    // characters
    val vulnerableVersionSanitized = vulnerableVersion?.trimStart('v', ' ', '\t')
    val componentVersionSanitized = componentVersion.trimStart('v', ' ', '\t')

    return when (vulnerableVersionSanitized) {
        null -> MatchPackageNoVersion
        componentVersionSanitized -> DefiniteMatch
        else -> DefinitelyNoMatch
    }
}

/** Matches the name of the vulnerable product with the name of the component. */
fun ProductInfo.matchesName(node: Node): MatchingConfidence {
    val name = this.branches.find { it.category == Csaf.Category3.product_name }?.name

    return when {
        name == null -> DefinitelyNoMatch
        name == node.name -> DefiniteMatch
        node.name.contains(name) -> PartialNameMatch
        else -> DefinitelyNoMatch
    }
}
