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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class VersionExtensionsTest {
    @Test
    fun testIsPreRelease() {
        assertFalse("1".isPreRelease)
        assertFalse("1.0.0".isPreRelease)
        assertTrue("1.0.0-alpha1".isPreRelease)
    }

    @Test
    fun testIsZeroVersionOrPreRelease() {
        assertFalse("1".isVersionZeroOrPreRelease)
        assertFalse("1.0.0".isVersionZeroOrPreRelease)
        assertTrue("0".isVersionZeroOrPreRelease)
        assertTrue("0.9.5".isVersionZeroOrPreRelease)
        assertTrue("1.0.0-alpha1".isVersionZeroOrPreRelease)
    }

    @Test
    fun testCompareVersionTo() {
        assertEquals(-1, "1".compareVersionTo("2"))
        assertEquals(-1, "1.0.0".compareVersionTo("2.0.0"))
        assertFailsWith<NumberFormatException> { assertEquals(-1, "1.0.0".compareVersionTo("2")) }
    }

    @Test
    fun testEqualsVersion() {
        assertFalse("1.0.0".equalsVersion("2"))
        assertFalse("1".equalsVersion("2"))
        assertTrue("2.0.0".equalsVersion("2.0.0+test", ignoreMetadata = true))
        assertTrue("2.0.0+test".equalsVersion("2.0.0+test", ignoreMetadata = false))
        assertFalse("2.0.0".equalsVersion("2.0.0+test", ignoreMetadata = false))
        assertTrue("2.0.0".equalsVersion("2.0.0-alpha1", ignorePreRelease = true))
        assertTrue("2.0.0-alpha1".equalsVersion("2.0.0-alpha1", ignorePreRelease = false))
        assertFalse("2.0.0".equalsVersion("2.0.0-alpha1", ignorePreRelease = false))
        assertFalse("1.0.0".equalsVersion("1.0.1"))
    }
}
