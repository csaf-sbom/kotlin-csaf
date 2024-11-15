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
package io.github.csaf.sbom.cvss

import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ExtensionTest {
    @Test
    fun testSeverity() {
        assertEquals(Csaf.BaseSeverity.CRITICAL, 10.0.toSeverity())
        assertEquals(Csaf.BaseSeverity.HIGH, 7.2.toSeverity())
        assertEquals(Csaf.BaseSeverity.MEDIUM, 5.1.toSeverity())
        assertEquals(Csaf.BaseSeverity.LOW, 0.4.toSeverity())
        assertEquals(Csaf.BaseSeverity.NONE, 0.0.toSeverity())
        assertFailsWith<IllegalArgumentException> { 20.0.toSeverity() }
    }
}
