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
package io.github.csaf.sbom.matching.old

import io.github.csaf.sbom.matching.MatcherNotSuitable
import io.github.csaf.sbom.matching.MatchingConfidence
import io.github.csaf.sbom.matching.MatchingTask
import io.github.csaf.sbom.matching.VulnerableProduct
import io.github.csaf.sbom.matching.parseCpe
import io.github.csaf.sbom.matching.properties.CpeProperty
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

/**
 * A [CPEMatchingTask] is a matching task that matches a CPE (specified in the security advisory)
 * against a component. It implements the [MatchingTask] interface.
 *
 * It uses the [CpeProperty.confidenceMatching] function to determine the matching confidence.
 */
object CPEMatchingTask : MatchingTask {
    override fun match(vulnerable: VulnerableProduct, component: Node): MatchingConfidence {
        // Check if the vulnerable product has a CPE
        val vulnerableCpe = vulnerable.cpe

        // If we have no CPE, we cannot match (for now)
        if (vulnerableCpe == null) {
            return MatcherNotSuitable
        }

        // Check, if we have a CPE to match against
        val cpeString =
            component.identifiers[SoftwareIdentifierType.CPE22.value]
                ?: component.identifiers[SoftwareIdentifierType.CPE23.value]
                ?: return MatcherNotSuitable
        val componentCpe = parseCpe(cpeString)

        // Check if the CPE is a match
        return CpeProperty(vulnerableCpe).confidenceMatching(CpeProperty(componentCpe))
    }
}
