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
import protobom.protobom.Node

/** Matches PURLs with confidence. */
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
 * A property that represents a PURL value.
 *
 * The confidence of a match (see [confidenceMatching]) is determined by comparing the PURL values.
 * - If the PURLs are equal according to the PURL specification, the confidence is [DefiniteMatch].
 * - Otherwise, the confidence is [DefinitelyNoMatch].
 *
 * We do not need to consider different sources, as a [Purl] can only come from
 * [PropertySource.PURL].
 */
class PurlProperty(value: Purl) : Property<Purl>(value, PropertySource.PURL) {
    override fun confidenceMatching(other: Property<Purl>): MatchingConfidence {
        return this.value.confidenceMatching(other.value)
    }
}

/** A little helper extension to convert a [Purl] to a [PurlProperty]. */
fun Purl.toProperty(): PurlProperty {
    return PurlProperty(this)
}

/**
 * The [PurlPropertyProvider] is a [PropertyProvider] that provides the CPE of a product as a
 * [PurlProperty].
 *
 * This is mostly a simple wrapper around the [PurlProperty] constructor.
 */
object PurlPropertyProvider : PropertyProvider<PurlProperty> {
    override fun provideProperty(vulnerable: ProductWithBranches): PurlProperty? {
        return null
    }

    override fun provideProperty(node: Node): PurlProperty? {
        return null
    }

    override fun provideProperty(cpe: Cpe): PurlProperty? {
        return null
    }

    override fun provideProperty(purl: Purl): PurlProperty? {
        return purl.toProperty()
    }
}
