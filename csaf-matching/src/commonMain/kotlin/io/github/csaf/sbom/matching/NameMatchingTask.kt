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
import io.github.csaf.sbom.validation.tests.ProductWithBranches
import protobom.protobom.Node

object NameMatchingTask : MatchingTask {
    override fun match(vulnerable: ProductWithBranches, component: Node): MatchingConfidence {
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

fun ProductWithBranches.matchesVersion(node: Node): MatchingConfidence {
    val version = this.branches.find { it.category == Csaf.Category3.product_version }?.name

    return when (version) {
        null -> MatchPackageNoVersion
        node.version -> DefiniteMatch
        else -> DefinitelyNoMatch
    }
}

fun ProductWithBranches.matchesName(node: Node): MatchingConfidence {
    val name = this.branches.find { it.category == Csaf.Category3.product_name }?.name

    return when {
        name == null -> DefinitelyNoMatch
        name == node.name -> DefiniteMatch
        node.name.contains(name) -> PartialNameMatch
        else -> DefinitelyNoMatch
    }
}
