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
package io.github.csaf.sbom

import kotlin.reflect.KProperty1
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import org.opentest4j.AssertionFailedError

typealias TestPair<R> = Pair<KProperty1<*, R>, R>

object PojoTestHelper {

    fun testAllNew(builder: (TestValueSourceNew) -> Unit) {
        val validValues = mutableListOf<Pair<String, *>>()
        val invalidValues = mutableListOf<Pair<String, *>>()
        assertNotNull(
            builder(
                object : TestValueSourceNew {
                    override fun <T> invoke(
                        defaultValue: T,
                        nullable: Boolean,
                        validList: List<T>?,
                        invalidList: List<T>?
                    ): T {
                        Thread.currentThread().stackTrace[3].toString().let { i ->
                            validList?.forEach { validValues += i to it }
                            invalidList?.forEach { invalidValues += i to it }
                            when (defaultValue!!::class) {
                                String::class -> invalidValues += i to ""
                                Set::class -> invalidValues += i to emptySet<Any>()
                                List::class -> invalidValues += i to emptyList<Any>()
                            }
                            if (nullable) {
                                validValues += i to null
                            }
                        }
                        return defaultValue
                    }
                }
            )
        )
        validValues.forEach { (vi, value) ->
            assertNotNull(
                builder(
                    object : TestValueSourceNew {
                        override fun <T> invoke(
                            defaultValue: T,
                            nullable: Boolean,
                            validList: List<T>?,
                            invalidList: List<T>?
                        ): T {
                            Thread.currentThread().stackTrace[3].toString().let { i ->
                                @Suppress("UNCHECKED_CAST")
                                return if (i == vi) value as T else defaultValue
                            }
                        }
                    }
                )
            )
        }
        invalidValues.forEach { (ii, value) ->
            try {
                assertFailsWith(IllegalArgumentException::class) {
                    builder(
                        object : TestValueSourceNew {
                            override fun <T> invoke(
                                defaultValue: T,
                                nullable: Boolean,
                                validList: List<T>?,
                                invalidList: List<T>?
                            ): T {
                                Thread.currentThread().stackTrace[3].toString().let { i ->
                                    @Suppress("UNCHECKED_CAST")
                                    return if (i == ii) value as T else defaultValue
                                }
                            }
                        }
                    )
                }
            } catch (afe: AssertionFailedError) {
                println("Expected IAE for $ii with value $value, but it passed without error.")
                throw afe
            }
        }
    }

    fun testAll(builder: (TestValueSource) -> Unit) {
        val validValues = mutableListOf<TestPair<*>>()
        val invalidValues = mutableListOf<TestPair<*>>()
        assertNotNull(
            builder(
                object : TestValueSource {
                    override fun <T> invoke(
                        property: KProperty1<*, T>,
                        defaultValue: T,
                        validList: List<T>?,
                        invalidList: List<T>?
                    ): T {
                        validList?.forEach { validValues += property to it }
                        invalidList?.forEach { invalidValues += property to it }
                        when (property.returnType.classifier) {
                            String::class -> invalidValues += property to ""
                            Set::class -> invalidValues += property to emptySet<T>()
                        }
                        if (property.returnType.isMarkedNullable) {
                            validValues += property to null
                        }
                        return defaultValue
                    }
                }
            )
        )
        validValues.forEach { (validProperty, value) ->
            assertNotNull(
                builder(
                    object : TestValueSource {
                        override fun <T> invoke(
                            property: KProperty1<*, T>,
                            defaultValue: T,
                            validList: List<T>?,
                            invalidList: List<T>?
                        ): T {
                            @Suppress("UNCHECKED_CAST")
                            return if (property == validProperty) value as T else defaultValue
                        }
                    }
                )
            )
        }
        invalidValues.forEach { (invalidProperty, value) ->
            assertFailsWith(IllegalArgumentException::class) {
                builder(
                    object : TestValueSource {
                        override fun <T> invoke(
                            property: KProperty1<*, T>,
                            defaultValue: T,
                            validList: List<T>?,
                            invalidList: List<T>?
                        ): T {
                            @Suppress("UNCHECKED_CAST")
                            return if (property == invalidProperty) value as T else defaultValue
                        }
                    }
                )
            }
        }
    }
}
