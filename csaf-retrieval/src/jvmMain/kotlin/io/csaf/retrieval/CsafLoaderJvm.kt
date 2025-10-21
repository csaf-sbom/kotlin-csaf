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

import io.ktor.client.engine.java.*
import java.net.ProxySelector
import java.net.http.HttpClient

actual fun defaultHttpClientEngine() = javaClientEngine(null)

/** Creates a [Java] client engine with an optional [ProxySelector]. */
fun javaClientEngine(selector: ProxySelector?) = Java.create { config { optionalProxy(selector) } }

/**
 * A little helper function that is extracted so we can test it without lazy loading the actual
 * config in the HTTP client.
 */
internal fun HttpClient.Builder.optionalProxy(selector: ProxySelector?) {
    if (selector != null) {
        proxy(selector)
    }
}
