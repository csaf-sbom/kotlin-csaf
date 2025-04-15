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
package io.github.csaf.sbom.matching.properties

import io.github.csaf.sbom.matching.Cpe
import io.github.csaf.sbom.matching.DefiniteMatch
import io.github.csaf.sbom.matching.DefinitelyNoMatch
import io.github.csaf.sbom.matching.MatchingConfidence
import io.github.csaf.sbom.matching.ProductWithBranches
import io.github.csaf.sbom.matching.Purl
import protobom.protobom.Node

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

/** A little helper extension to convert a [Cpe] to a [CpeProperty]. */
fun Cpe.toProperty(): CpeProperty {
    return CpeProperty(this)
}

/**
 * The [CpePropertyProvider] is a [PropertyProvider] that provides the CPE of a product as a
 * [CpeProperty].
 *
 * This is mostly a simple wrapper around the [CpeProperty] constructor.
 */
object CpePropertyProvider : PropertyProvider<CpeProperty> {
    override fun provideProperty(vulnerable: ProductWithBranches): CpeProperty? {
        return null
    }

    override fun provideProperty(node: Node): CpeProperty? {
        return null
    }

    override fun provideProperty(cpe: Cpe): CpeProperty? {
        return cpe.toProperty()
    }

    override fun provideProperty(purl: Purl): CpeProperty? {
        return null
    }
}
