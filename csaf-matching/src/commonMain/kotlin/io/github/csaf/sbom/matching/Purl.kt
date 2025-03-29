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

import protobom.protobom.Node
import protobom.protobom.SoftwareIdentifierType

expect class Purl(purl: String) {
    fun canonicalize(): String

    fun getScheme(): String?

    fun getType(): String?

    fun getNamespace(): String?

    fun getName(): String

    fun getVersion(): String

    fun getQualifiers(): MutableMap<String, String>?

    fun getSubpath(): String?
}

val Node.purl: Purl?
    get() {
        return this.identifiers[SoftwareIdentifierType.PURL.value]?.let { Purl(it) }
    }
