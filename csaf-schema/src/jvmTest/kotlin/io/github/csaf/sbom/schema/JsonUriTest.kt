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
package io.github.csaf.sbom.schema

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsonUriTest {

    @Test
    fun `test equals with different type`() {
        val jsonUri = JsonUri("https://example.com")
        val differentTypeObject = "Some String"
        assertFalse(jsonUri.equals(null), "JsonUri should not be equal to null")
        assertFalse(
            jsonUri.equals(differentTypeObject),
            "JsonUri should not be equal to an object of a different type",
        )
    }

    @Test
    fun `test equals with same instance`() {
        val jsonUri = JsonUri("https://example.com")
        @Suppress("KotlinConstantConditions")
        assertTrue(jsonUri == jsonUri, "JsonUri should be equal to itself")
    }

    @Test
    fun `test equals with another JsonUri with same value`() {
        val jsonUri1 = JsonUri("https://example.com")
        val jsonUri2 = JsonUri("https://example.com")
        assertTrue(jsonUri1 == jsonUri2, "JsonUri with the same value should be equal")
    }
}
