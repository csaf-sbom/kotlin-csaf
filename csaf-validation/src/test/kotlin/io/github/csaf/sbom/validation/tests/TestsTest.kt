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

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationSuccessful
import io.github.csaf.sbom.validation.requirements.goodCsaf
import kotlin.io.path.Path
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.serialization.json.Json

class TestsTest {
    @Test
    fun test611() {
        val test = Test611MissingDefinitionOfProductID
        val fail =
            Json.decodeFromString<Csaf>(
                Path(
                        "../csaf/csaf_2.0/test/validator/data/mandatory/oasis_csaf_tc-csaf_2_0-2021-6-1-01-01.json"
                    )
                    .readText()
            )

        assertEquals(
            ValidationFailed(
                listOf("The following IDs are not defined: CSAFPID-9080700,CSAFPID-9080701")
            ),
            test.test(fail)
        )
    }

    @Test
    fun test621() {
        val test = Test621UnusedDefinitionOfProductID
        val fail =
            Json.decodeFromString<Csaf>(
                Path(
                        "../csaf/csaf_2.0/test/validator/data/optional/oasis_csaf_tc-csaf_2_0-2021-6-2-01-01.json"
                    )
                    .readText()
            )

        assertEquals(
            ValidationFailed(listOf("The following IDs are not used: CSAFPID-9080700")),
            test.test(fail)
        )
    }

    @Test
    fun testAllGood() {
        val good = goodCsaf()
        val tests = listOf(Test611MissingDefinitionOfProductID, Test621UnusedDefinitionOfProductID)
        tests.forEach {
            assertEquals(
                ValidationSuccessful,
                it.test(good),
                "${it::class.simpleName} was not successful"
            )
        }
    }
}
