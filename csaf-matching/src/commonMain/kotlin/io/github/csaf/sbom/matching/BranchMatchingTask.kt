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

import io.github.csaf.sbom.schema.generated.Csaf
import protobom.protobom.Node

/**
 * A [BranchMatchingTask] is a [MatchingTask] that matches a [VulnerableProduct] against a [Node]
 * based on the information contained in [Csaf.Branche].
 */
object BranchMatchingTask : MatchingTask {
    override fun match(vulnerable: VulnerableProduct, component: Node): MatchingConfidence {
        // First, try to match the name. If we have a definite mismatch we can exit early
        var match: MatchingConfidence = vulnerable.matchesName(component)
        if (match == DefinitelyNoMatch) {
            return DefinitelyNoMatch
        }

        // Then, try to match the version. If we have a definite mismatch we can exit early
        match = match.times(vulnerable.matchesVersion(component))
        if (match == DefinitelyNoMatch) {
            return DefinitelyNoMatch
        }

        return match
    }
}

fun VulnerableProduct.matchesVersion(node: Node): MatchingConfidence {
    // Extract a vulnerable version from the branches
    val vulnerableVersion =
        this.branches.find { it.category == Csaf.Category3.product_version }?.name
    val componentVersion = node.version

    // Extract a vulnerable version range from the branches...
    val vulnerableVersionRange =
        this.branches.find { it.category == Csaf.Category3.product_version_range }?.name
    // ...and try to parse it as a vers range
    val vers = vulnerableVersionRange?.let { parseVers(it) }

    // In an effort to sanitize the version strings, we remove training zeros and leading 'v'
    // characters
    val vulnerableVersionSanitized = vulnerableVersion?.trimStart('v', ' ', '\t')
    val componentVersionSanitized = componentVersion.trimStart('v', ' ', '\t')

    // Match based on the fixed version first
    val match =
        when (vulnerableVersionSanitized) {
            // We are only looking at version ranges if the version is not set
            null -> {
                return when (vers) {
                    // If neither version nor version range is set, we assume that the whole package
                    // is affected, but our match is less confident
                    null -> MatchPackageNoVersion
                    // If a version range is set, we can use it to compare it against our
                    // (sanitized) component version
                    else ->
                        if (vers.contains(componentVersionSanitized)) DefiniteMatch
                        else DefinitelyNoMatch
                }
            }
            // If the versions matches our (sanitized) component version, we have a definite match
            componentVersionSanitized -> DefiniteMatch
            // Otherwise, we have a definite mismatch
            else -> DefinitelyNoMatch
        }

    return match
}

/** Matches the name of the vulnerable product with the name of the component. */
fun VulnerableProduct.matchesName(node: Node): MatchingConfidence {
    val name = this.branches.find { it.category == Csaf.Category3.product_name }?.name

    return when {
        name == null -> DefinitelyNoMatch
        name == node.name -> DefiniteMatch
        node.name.contains(name) -> PartialStringMatch
        else -> DefinitelyNoMatch
    }
}
