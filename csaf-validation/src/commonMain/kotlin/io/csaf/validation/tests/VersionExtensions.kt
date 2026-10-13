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
package io.csaf.validation.tests

import net.swiftzer.semver.SemVer

/**
 * Checks, if this string represents either a "zero" version, e.g. "0", "0.x.y" or has a pre-release
 * part such as "1.2.3-alpha1".
 */
val String.isVersionZeroOrPreRelease: Boolean
    get() = versionOrMajorVersion == 0 || isPreRelease

/**
 * Retrieves the version as an [Int] in case it is a simple version, such as "0" or "1" or the major
 * version, in case it is a semantic version. In this case, the version "0.x.y" will return "0".
 */
val String.versionOrMajorVersion: Int
    get() = toSemVer()?.major ?: toInt()

/**
 * Checks, if this string represents a semantic version containing a pre-release part, e.g.
 * "1.2.3-alpha".
 */
val String.isPreRelease: Boolean
    get() = toSemVer()?.preRelease != null

/** Tries to convert this string into a semantic version, represented by a [SemVer] object. */
fun String.toSemVer(): SemVer? {
    return SemVer.parseOrNull(this)
}

/**
 * Compares two version strings. Returns the difference by either [SemVer.compareTo] or
 * [Int.compareTo].
 */
fun String.compareVersionTo(version2: String): Int {
    val semver1 = SemVer.parseOrNull(this)
    val semver2 = SemVer.parseOrNull(version2)
    return if (semver1 != null && semver2 != null) {
        semver1.compareTo(semver2)
    } else {
        this.toInt() - version2.toInt()
    }
}

/**
 * Equality check between two versions with extra options.
 *
 * @param ignoreMetadata When specified, it ignores the [SemVer.buildMetadata] part.
 * @param ignorePreRelease When specified, it ignores the [SemVer.preRelease] part.
 * @return true, if the versions are the same.
 */
fun String.equalsVersion(
    version2: String,
    ignoreMetadata: Boolean = true,
    ignorePreRelease: Boolean = false,
): Boolean {
    val semver1 = SemVer.parseOrNull(this)
    val semver2 = SemVer.parseOrNull(version2)

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
