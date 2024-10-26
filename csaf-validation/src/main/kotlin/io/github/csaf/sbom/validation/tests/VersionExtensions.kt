/*
 * Copyright (c) 2024, The Authors. All rights reserved.
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
package io.github.csaf.sbom.validation.tests

import net.swiftzer.semver.SemVer

val String.isZeroVersionOrPreRelease: Boolean
    get() {
        val semver = SemVer.parseOrNull(this)
        return this.versionOrMajorVersion == 0 || semver?.preRelease != null
    }

val String.versionOrMajorVersion: Int
    get() {
        val semver = SemVer.parseOrNull(this)
        return if (semver != null) {
            semver.major
        } else {
            this.toInt()
        }
    }

val String.isPreRelease: Boolean
    get() {
        val semver = SemVer.parseOrNull(this)
        return semver?.preRelease != null
    }

fun String.compareVersionTo(version2: String): Int {
    var semver1 = SemVer.parseOrNull(this)
    var semver2 = SemVer.parseOrNull(version2)
    return if (semver1 != null && semver2 != null) {
        semver1.compareTo(semver2)
    } else {
        this.toInt() - version2.toInt()
    }
}

fun String.equalsVersion(
    version2: String,
    ignoreMetadata: Boolean = true,
    ignorePreRelease: Boolean = false
): Boolean {
    var semver1 = SemVer.parseOrNull(this)
    var semver2 = SemVer.parseOrNull(version2)

    return if (semver1 != null && semver2 != null) {
        semver1.major == semver2.major &&
            semver1.minor == semver2.minor &&
            semver1.patch == semver2.patch &&
            (ignoreMetadata || semver1.buildMetadata == semver2.buildMetadata) &&
            (ignorePreRelease || semver1.preRelease == semver2.preRelease)
    } else {
        this == version2
    }
}
