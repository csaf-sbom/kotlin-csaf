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
package io.csaf.matching

import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

/**
 * An interface for a class that represents a
 * [CPE (Common Platform Enumeration)](https://nvd.nist.gov/products/cpe).
 */
expect interface Cpe {
    fun matches(other: Cpe): Boolean

    fun getVendor(): String

    fun getProduct(): String

    fun getVersion(): String
}

/** Parses a CPE string into a [Cpe] object. */
expect fun parseCpe(cpe: String): Cpe

/** A [Cpe] object that is derived from a [Node.identifiers]. */
val Node.cpe: Cpe?
    get() {
        return (this.identifiers[SoftwareIdentifierType.CPE22.value]
                ?: this.identifiers[SoftwareIdentifierType.CPE23.value])
            ?.let { parseCpe(it) }
    }
