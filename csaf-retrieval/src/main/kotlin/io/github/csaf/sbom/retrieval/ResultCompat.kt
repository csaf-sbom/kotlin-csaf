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
@file:Suppress("unused", "MemberVisibilityCanBePrivate")

package io.github.csaf.sbom.retrieval

/**
 * ResultCompat.
 *
 * It is intended to solve the problem of being unable to obtain [kotlin.Result] in java.
 */
class ResultCompat<T>(private val result: Result<T>) {

    companion object {
        /** Returns a [Result] that encapsulates the given value as successful value. */
        @JvmStatic fun <T> success(value: T): ResultCompat<T> = ResultCompat(Result.success(value))

        /** Returns a [Result] that encapsulates the given [Throwable] as failure. */
        @JvmStatic
        fun <T> failure(throwable: Throwable): ResultCompat<T> =
            ResultCompat(Result.failure(throwable))
    }

    /** Returns `true` if this [Result] represents a successful outcome. */
    val isSuccess: Boolean
        get() = result.isSuccess

    /** Returns `true` if this [Result] represents a failed outcome. */
    val isFailure: Boolean
        get() = result.isFailure

    /** @see Result.getOrNull */
    fun getOrNull(): T? = result.getOrNull()

    /** @see Result.exceptionOrNull */
    fun exceptionOrNull(): Throwable? = result.exceptionOrNull()

    override fun toString(): String =
        if (isSuccess) "ResultCompat(value = ${getOrNull()})"
        else "ResultCompat(error = ${exceptionOrNull().toString()})"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ResultCompat<*>) return false
        return result == other.result
    }

    override fun hashCode() = result.hashCode()
}
