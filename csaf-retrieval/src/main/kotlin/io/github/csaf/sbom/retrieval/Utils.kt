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

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

val CSAF_ENTRY_REGEX = Regex("CSAF: (https://.*)")

/**
 * An async replacement for `Iterable.map()`, which processes all elements in parallel using
 * coroutines. The function preserves the order of the `Iterable` it is applied on.
 *
 * @param T The input type of the transformation.
 * @param R The output type of the transformation.
 * @param transformation The mapping transformation to apply asynchronously to every element.
 * @return A `List` of transformation results.
 * @receiver An iterable of elements to map.
 */
suspend fun <T, R> Iterable<T>.mapAsync(transformation: suspend (T) -> R): List<R> =
    coroutineScope {
        this@mapAsync.map { async { transformation(it) } }.awaitAll()
    }

/**
 * A helper function to asynchronously obtain a `Result` from a code block that may succeed or throw
 * a `Throwable`. Upon success, the resulting value of the code block will be return as a successful
 * `Result`. Upon error, the thrown `Throwable` will be wrapped into the returned `Result` instead.
 *
 * @param T The type wrapped into the `Result` on success.
 * @param supplier The code block producing the result of type `T`.
 * @return The `Result`, wrapping a `T` object or a `Throwable`.
 */
suspend fun <T> Result.Companion.of(supplier: suspend () -> T): Result<T> {
    return try {
        success(supplier())
    } catch (t: Throwable) {
        failure(t)
    }
}
