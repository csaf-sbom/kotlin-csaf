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
package io.github.csaf.sbom.validation

import io.github.csaf.sbom.schema.KoverIgnore
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.tests.informativeTests
import io.github.csaf.sbom.validation.tests.mandatoryTests
import io.github.csaf.sbom.validation.tests.optionalTests
import java.time.Duration
import java.time.Instant
import kotlin.io.path.Path
import kotlin.io.path.readText
import kotlinx.serialization.json.Json

@KoverIgnore("Entry point for demo purposes only")
fun main(args: Array<String>) {
    val path = Path(args[0])
    val doc = Json.decodeFromString<Csaf>(path.readText())

    println("Analyzing file ${path}...\n")

    val globalStart = Instant.now()

    val allTests =
        mapOf(
            mandatoryTests to "mandatory",
            optionalTests to "optional",
            informativeTests to "informative",
        )

    for (entry in allTests) {
        println("== ${entry.value.uppercase()} TESTS ==")

        for (test in entry.key) {
            val start = Instant.now()
            val result = test.test(doc)
            println(
                "Test ${test::class.simpleName}: $result. It took ${
                    Duration.between(start, Instant.now()).toMillis()
                } ms"
            )
        }

        println("")
    }

    println(
        "Executing all tests took ${Duration.between(globalStart, Instant.now()).toMillis()} ms"
    )
}
