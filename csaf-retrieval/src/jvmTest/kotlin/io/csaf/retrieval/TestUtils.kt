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
package io.csaf.retrieval

import io.ktor.client.engine.mock.*
import io.ktor.http.*
import java.net.URL

fun Any.getResourceUrl(resourcePath: String): URL? = javaClass.classLoader.getResource(resourcePath)

fun mockEngine() = MockEngine { request ->
    val host = request.url.host
    val file =
        request.url.fullPath.trimStart('/').let {
            // A little trick to serve the metadata JSON on the DNS path
            if (it == "") "index.json" else it
        }
    val response = getResourceUrl(("$host/$file").trimStart('/'))

    if (response == null) {
        respond(content = "Not Found", status = HttpStatusCode.NotFound)
    } else {
        respond(
            content = response.readText(),
            status = HttpStatusCode.OK,
            headers = headersOf(HttpHeaders.ContentType, "application/json"),
        )
    }
}

fun tooManyRequestsEngineFactory(failures: Int = 1): MockEngine {
    var attempt = 0

    return MockEngine { request ->
        attempt++

        if (attempt <= failures) {
            respondError(
                status = HttpStatusCode.TooManyRequests,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        } else {
            respond(
                content = "Success on attempt $attempt",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Text.Plain.toString()),
            )
        }
    }
}
