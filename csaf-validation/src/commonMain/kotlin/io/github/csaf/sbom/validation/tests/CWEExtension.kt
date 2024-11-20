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
package io.github.csaf.sbom.validation.tests

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream

@Serializable data class CWE(val id: String, val name: String)

@Serializable data class CWEList(val weaknesses: List<CWE>)

val weaknesses = loadCWEData()

@OptIn(ExperimentalSerializationApi::class)
internal fun loadCWEData(path: String = "/cwe.json"): Map<String, CWE> {
    val stream = object {}.javaClass.getResourceAsStream(path)
    return if (stream != null) {
        Json.decodeFromStream<CWEList>(stream).weaknesses.associateBy { it.id }
    } else {
        mapOf()
    }
}
