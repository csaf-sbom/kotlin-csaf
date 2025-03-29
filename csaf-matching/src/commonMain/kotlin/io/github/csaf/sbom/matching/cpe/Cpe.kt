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
package io.github.csaf.sbom.matching.cpe

import io.github.csaf.sbom.matching.DefiniteMatch
import io.github.csaf.sbom.matching.DefinitelyNoMatch
import io.github.csaf.sbom.matching.MatchingConfidence
import io.github.csaf.sbom.matching.properties.Property
import io.github.csaf.sbom.matching.provider.PropertySource
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

expect interface Cpe {
    fun matches(other: Cpe): Boolean

    fun getVendor(): String
}

expect fun parseCpe(cpe: String): Cpe

val Node.cpe: Cpe?
    get() {
        return (this.identifiers[SoftwareIdentifierType.CPE22.value]
                ?: this.identifiers[SoftwareIdentifierType.CPE23.value])
            ?.let { parseCpe(it) }
    }

/**
 * A property that represents a CPE value.
 *
 * The confidence of a match (see [confidenceMatching]) is determined by comparing the CPE values.
 * - If the CPEs are equal according to the CPE specification, the confidence is [DefiniteMatch].
 * - Otherwise, the confidence is [DefinitelyNoMatch].
 *
 * We do not need to consider different sources, as a [CpeProperty] can only come from
 * [PropertySource.CPE].
 */
class CpeProperty(value: Cpe) : Property<Cpe>(value, PropertySource.CPE) {
    override fun confidenceMatching(other: Property<Cpe>): MatchingConfidence {
        // Check if the CPEs are equal according to the CPE specification, then we have a definite
        // match
        if (this.value.matches(other.value)) {
            return DefiniteMatch
        }

        return DefinitelyNoMatch
    }
}
