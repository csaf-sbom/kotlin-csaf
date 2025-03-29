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

import io.github.csaf.sbom.matching.*

val dashUnderscoreRegex = Regex("[_-]")

/**
 * A property that represents a string value.
 *
 * The confidence of a match (see [confidenceMatching]) is determined by comparing the string
 * values.
 * - If the strings are equal, the confidence is [DefiniteMatch].
 * - If the strings are equal ignoring case, the confidence is [CaseInsensitiveMatch].
 * - Otherwise, the confidence is [DefinitelyNoMatch].
 *
 * Finally, if the sources of the properties are different, the confidence is multiplied by
 * [DifferentSources].
 */
class StringProperty(value: String, source: PropertySource) : Property<String>(value, source) {
    override fun confidenceMatching(other: Property<String>): MatchingConfidence {
        val contentMatch =
            when {
                this.value == other.value -> DefiniteMatch
                this.value.lowercase() == other.value.lowercase() -> CaseInsensitiveMatch
                this.value.lowercase().replace(dashUnderscoreRegex, " ") ==
                    other.value.lowercase().replace(dashUnderscoreRegex, " ") ->
                    CaseInsensitiveIgnoreDashMatch
                other.value.contains(this.value) -> PartialStringMatch
                else -> DefinitelyNoMatch
            }

        return if (this.source == other.source) {
            contentMatch
        } else {
            contentMatch * DifferentSources(listOf(this.source, other.source))
        }
    }
}

/** A little helper extension to convert a nullable string to a [StringProperty]. */
fun String.toProperty(source: PropertySource): StringProperty {
    return StringProperty(this, source)
}
