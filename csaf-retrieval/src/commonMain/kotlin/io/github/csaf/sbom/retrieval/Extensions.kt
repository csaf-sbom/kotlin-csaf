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
package io.github.csaf.sbom.retrieval

import io.github.csaf.sbom.schema.generated.Csaf

/** A platform independent function to compute the SHA-256 hash of a string. */
expect fun sha256(s: String): ByteArray

/** Returns a hexadecimal representation of the input byte array. */
fun hex(input: ByteArray): String {
    return input.joinToString("") { "%02x".format(it) }
}

/**
 * This function tries to compute a unique (string-based) ID for a given [Csaf] document. The main
 * use-case is the usage of this as a primary key in a database.
 *
 * In order to compute the ID, we concatenate the following parts (with a dash as separator):
 * - The prefix "CSAF"
 * - The first 8 characters of the SHA-256 hash of the publisher namespace
 * - The tracking ID (which needs to be unique within the publisher namespace)
 *
 * @param this the [Csaf] document to compute the ID for.
 * @return the computed unique ID.
 */
val Csaf.uniqueID
    get(): String {
        return "CSAF-" +
            hex(sha256(this.document.publisher.namespace.toString())).substring(0, 8) +
            "-" +
            this.document.tracking.id
    }
