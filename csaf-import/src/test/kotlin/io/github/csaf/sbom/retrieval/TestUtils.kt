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
package io.github.csaf.sbom.retrieval

import io.ktor.client.engine.mock.*
import io.ktor.http.*

fun mockEngine() = MockEngine { request ->
    var host = request.url.host
    var file = request.url.fullPath.trimStart('/')
    // A little trick to serve the metadata JSON on the DNS path
    if (file == "") {
        file = "index.json"
    }
    var resourcePath = ("$host/$file").trimStart('/')
    var response = javaClass.classLoader.getResource(resourcePath)

    if (response == null) {
        respond(content = "Not Found", status = HttpStatusCode.NotFound)
    } else {
        respond(
            content = response.readText(),
            status = HttpStatusCode.OK,
            headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
    }
}
