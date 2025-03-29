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
package io.github.csaf.sbom.matching.provider

import io.github.csaf.sbom.matching.gatherVulnerableProducts
import io.github.csaf.sbom.matching.linuxProductTree
import io.github.csaf.sbom.matching.properties.toProperty
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

class PropertyProviderTest {
    @Test
    fun testGatherProperties() {
        val linux40 =
            linuxProductTree
                .gatherVulnerableProducts { it.product_id == "LINUX_KERNEL_4_0" }
                .firstOrNull()
        assertNotNull(linux40)

        val vulnerable = VendorProvider.gatherVulnerableProperties(linux40)
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

        val toMatch = VendorProvider.gatherComponentProperties(linuxComponent)
        assertNotNull(toMatch)
    }
}
