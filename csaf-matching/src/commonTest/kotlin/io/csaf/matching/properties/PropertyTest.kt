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
package io.csaf.matching.properties

import io.csaf.matching.linux40
import kotlin.test.*
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

class PropertyTest {
    @Test
    fun testGatherProperties() {
        val vulnerable = VendorPropertyProvider.gatherVulnerableProperties(linux40)
        assertEquals(
            mapOf(
                PropertySource.OTHER to "Linux".toProperty(PropertySource.OTHER),
                PropertySource.CPE to "linux".toProperty(PropertySource.CPE),
            ),
            vulnerable,
        )

        val linuxComponent =
            Node(
                name = "Kernel",
                version = "4.0",
                identifiers =
                    mapOf(
                        SoftwareIdentifierType.CPE23.value to
                            "cpe:2.3:o:linux:linux_kernel:4.0:*:*:*:*:*:*:*"
                    ),
            )

        val toMatch = VendorPropertyProvider.gatherComponentProperties(linuxComponent)
        assertNotNull(toMatch)
    }

    @Test
    fun testEquals() {
        val p1 = "test".toProperty(PropertySource.OTHER)
        val p2 = "test2".toProperty(PropertySource.OTHER)
        val p3 = "test".toProperty(PropertySource.CPE)
        assertEquals(p1, p1)
        assertNotEquals(p1, p2)
        assertNotEquals(p1, p3)
        assertNotEquals(p1, Any())
    }
}
