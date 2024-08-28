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
import io.github.csaf.sbom.mapAsync
import io.github.csaf.sbom.of
import kotlin.test.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest

class UtilsTest {
    @Test
    fun testMapAsync() = runTest {
        val arrivalList = mutableListOf<Int>()
        assertContentEquals(
            listOf(2000, 1000, 0),
            listOf(200, 100, 0).mapAsync {
                delay(it.toLong())
                arrivalList += it
                it * 10
            },
            "Async mapping failed or did not preserve element order."
        )
        assertContentEquals(
            listOf(0, 100, 200),
            arrivalList,
            "Async mappings did not return in expected order."
        )
    }

    @Test
    fun testResultOf() = runTest {
        assertSame(
            "Success",
            Result.of {
                    delay(1000)
                    "Success"
                }
                .getOrNull()
        )
        val throwable = assertFails {
            Result.of {
                    delay(1000)
                    throw RuntimeException("Failed")
                }
                .getOrThrow()
        }
        assertSame("Failed", throwable.message)
    }
}
