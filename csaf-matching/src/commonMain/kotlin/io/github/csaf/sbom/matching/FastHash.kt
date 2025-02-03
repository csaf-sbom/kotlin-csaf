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

/**
 * A wrapper class for usage of immutable objects as Keys in [HashMap]s/[HashSet]s. The wrapper
 * calls hashCode() of the wrapped object only once and caches its result. This is valid for
 * immutable objects and speeds up [HashMap]s/[HashSet]s operations considerably.
 *
 * @property o The wrapped immutable object
 * @constructor Create empty Hash csaf
 */
class FastHash<T>(val o: T) {
    private val hash = o.hashCode()

    override fun hashCode(): Int {
        return hash
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as FastHash<T>

        return o == other.o
    }

    override fun toString(): String {
        return o.toString()
    }
}
