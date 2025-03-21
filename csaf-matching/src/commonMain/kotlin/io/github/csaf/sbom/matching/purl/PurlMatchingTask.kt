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

const val DEFINITELY_NO_MATCH = 0.0f
const val DEFINITE_MATCH = 1.0f
const val MATCH_PACKAGE_NO_VERSION = 0.7f

fun Purl.matches(other: Purl): Float {
    // All of these must match, otherwise we definitely not have a match. We can skip comparing the
    // scheme because the schema is already checked in the Purl constructor.
    if (this.getType() != other.getType()) return DEFINITELY_NO_MATCH
    if (this.getNamespace() != other.getNamespace()) return DEFINITELY_NO_MATCH
    if (this.getName() != other.getName()) return DEFINITELY_NO_MATCH

    // If the version is not set, we have a match, but we are not completely sure. It could either
    // mean that someone forgot to set the version or that that all versions are affected.
    if (this.getVersion() == null) return MATCH_PACKAGE_NO_VERSION

    // If the version is set, we have a match if the versions are equal
    if (this.getVersion() == other.getVersion()) return DEFINITE_MATCH

    return DEFINITELY_NO_MATCH
}

class PurlMatchingTask(val purl: Purl) : MatchingTask {

    override fun match(component: Node): Float {
        // Check, if we have a purl to match against
        val componentPurl =
            component.identifiers[SoftwareIdentifierType.PURL.value]?.let { Purl(it) }
        if (componentPurl == null) {
            return DEFINITELY_NO_MATCH
        }

        return purl.matches(componentPurl)
    }
}
