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
package io.csaf.schema

import java.net.URI
import kotlinx.serialization.Serializable

@Serializable(UriSerializer::class)
actual class JsonUri(private var value: URI) {
    actual constructor(s: String) : this(URI.create(s))

    actual companion object {
        actual fun create(s: String): JsonUri {
            return JsonUri(URI.create(s))
        }
    }

    override fun toString(): String {
        return value.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as JsonUri

        return value == other.value
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }
}
