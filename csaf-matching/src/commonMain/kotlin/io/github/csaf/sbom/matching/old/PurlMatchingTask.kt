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

import io.github.csaf.sbom.matching.*

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
