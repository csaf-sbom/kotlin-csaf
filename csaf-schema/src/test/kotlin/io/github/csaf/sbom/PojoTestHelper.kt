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
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

object PojoTestHelper {
    fun testAll(builder: (TestValueSource) -> Unit) {
        val validValues = mutableListOf<Pair<KProperty1<*, *>, Any?>>()
        val invalidValues = mutableListOf<Pair<KProperty1<*, *>, Any?>>()
        assertDoesNotThrow {
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
        }
        println(validValues)
        println(invalidValues)
        validValues.forEach { (validProperty, value) ->
            assertDoesNotThrow {
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
            }
        }
        invalidValues.forEach { (invalidProperty, value) ->
            assertThrows<IllegalArgumentException> {
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
