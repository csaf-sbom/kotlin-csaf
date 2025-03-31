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

import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.assertNotNull

val linuxVendorBranch =
    Csaf.Branche(
        name = "Linux",
        category = Csaf.Category3.vendor,
        branches =
            listOf(
                Csaf.Branche(
                    category = Csaf.Category3.product_name,
                    name = "Linux Kernel",
                    branches =
                        listOf(
                            Csaf.Branche(
                                product =
                                    Csaf.Product(
                                        name = "Linux Kernel 4.0",
                                        product_id = "LINUX_KERNEL_4_0",
                                        product_identification_helper =
                                            Csaf.ProductIdentificationHelper(
                                                cpe =
                                                    "cpe:2.3:o:linux:linux_kernel:4.0:*:*:*:*:*:*:*"
                                            ),
                                    ),
                                category = Csaf.Category3.product_version,
                                name = "4.0",
                            )
                        ),
                ),
                Csaf.Branche(
                    category = Csaf.Category3.product_name,
                    name = "Linux Kernel",
                    branches =
                        listOf(
                            Csaf.Branche(
                                product =
                                    Csaf.Product(
                                        name = "Linux Kernel >= 4.0",
                                        product_id = "LINUX_KERNEL_GTE_4_0",
                                    ),
                                category = Csaf.Category3.product_version_range,
                                name = "vers:deb/>=4.0",
                            )
                        ),
                ),
                Csaf.Branche(
                    product =
                        Csaf.Product(
                            name = "Linux Kernel",
                            product_id = "LINUX_KERNEL_UNSPECIFIED",
                        ),
                    category = Csaf.Category3.product_name,
                    name = "Linux Kernel",
                ),
            ),
    )

val linuxProductTree = Csaf.ProductTree(branches = listOf(linuxVendorBranch))

/**
 * Describes a [VulnerableProduct] with the following attributes:
 * - vendor: Linux
 * - product: Linux Kernel
 * - version: 4.0
 * - cpe: cpe:2.3:o:linux:linux_kernel:4.0:*:*:*:*:*:*:*
 */
val linux40 =
    assertNotNull(
        goodCsaf(productTree = linuxProductTree)
            .gatherVulnerableProducts { it.product_id == "LINUX_KERNEL_4_0" }
            .firstOrNull()
    )

/**
 * Describes a [VulnerableProduct] with the following attributes:
 * - vendor: Linux
 * - product: Linux Kernel
 * - version: >= 4.0
 */
val linuxGTE40 =
    assertNotNull(
        goodCsaf(productTree = linuxProductTree)
            .gatherVulnerableProducts { it.product_id == "LINUX_KERNEL_GTE_4_0" }
            .firstOrNull()
    )

/**
 * Describes a [VulnerableProduct] with the following attributes:
 * - vendor: Linux
 * - product: Linux Kernel
 * - version: unspecified
 */
val linuxUnspecified =
    assertNotNull(
        goodCsaf(productTree = linuxProductTree)
            .gatherVulnerableProducts { it.product_id == "LINUX_KERNEL_UNSPECIFIED" }
            .firstOrNull()
    )
