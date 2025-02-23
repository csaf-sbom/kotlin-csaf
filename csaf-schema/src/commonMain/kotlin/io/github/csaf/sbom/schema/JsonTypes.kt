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
package io.github.csaf.sbom.schema

import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

/** A platform independent representation of a URI / URL used in JSON documents. */
@Serializable(UriSerializer::class)
expect class JsonUri {
    constructor(s: String)

    companion object {
        /** A platform independent way to create a [JsonUri] from a string. */
        fun create(s: String): JsonUri
    }

    /** The string representation of this [JsonUri], must contain the full URI. */
    override fun toString(): String
}

fun epoch(): Instant {
    return Instant.fromEpochMilliseconds(0)
}
