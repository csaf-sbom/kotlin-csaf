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
package io.github.csaf.sbom.matching

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Test class for the FastHash class.
 *
 * FastHash is a generic class that wraps an object and provides a precomputed hashCode, custom
 * equality logic, and a string representation delegating to the wrapped object.
 */
class FastHashTest {

    @Test
    fun testHashCodeConsistency() {
        val input = "testString"
        val fastHash = FastHash(input)
        assertEquals(
            input.hashCode(),
            fastHash.hashCode(),
            "hashCode should match the input's hashCode.",
        )
    }

    @Test
    fun testEqualsSameInstance() {
        val input = "testString"
        val fastHash = FastHash(input)
        @Suppress("KotlinConstantConditions")
        assertTrue(fastHash == fastHash, "An instance should be equal to itself.")
    }

    @Test
    fun testEqualsDifferentInstanceSameValue() {
        val input = "testString"
        val fastHash1 = FastHash(input)
        val fastHash2 = FastHash(input)
        assertTrue(fastHash1 == fastHash2, "Instances with the same wrapped value should be equal.")
    }

    @Test
    fun testEqualsDifferentInstanceDifferentValue() {
        val fastHash1 = FastHash("testString1")
        val fastHash2 = FastHash("testString2")
        assertFalse(
            fastHash1 == fastHash2,
            "Instances with different wrapped values should not be equal.",
        )
    }

    @Test
    fun testEqualsNull() {
        val fastHash = FastHash("testString")
        assertFalse(fastHash.equals(null), "An instance should not be equal to null.")
    }

    @Test
    fun testEqualsDifferentClass() {
        val fastHash = FastHash("testString")
        val otherObject = "testString"
        assertFalse(
            fastHash.equals(otherObject),
            "An instance should not be equal to an object of a different class.",
        )
    }

    @Test
    fun testToStringDelegation() {
        val input = "testString"
        val fastHash = FastHash(input)
        assertEquals(
            input,
            fastHash.toString(),
            "toString should delegate to the wrapped object's toString.",
        )
    }

    @Test
    fun testToStringNull() {
        val fastHash = FastHash(null)
        assertEquals("null", fastHash.toString(), "toString should return 'null' for null input.")
    }

    @Test
    fun testNullHashCode() {
        val fastHash = FastHash(null)
        assertEquals(0, fastHash.hashCode(), "hashCode should return 0 for null input.")
    }
}
