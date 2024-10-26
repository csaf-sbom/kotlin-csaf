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
import io.github.csaf.sbom.validation.ValidationSuccessful
import io.github.csaf.sbom.validation.assertValidationFailed
import io.github.csaf.sbom.validation.assertValidationSuccessful
import io.github.csaf.sbom.validation.requirements.goodCsaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** The path to the test folder for the CSAF 2.0 tests. */
var testFolder: String = "../csaf/csaf_2.0/test/validator/data/"

/**
 * Short utility function to construct the path to the test file based on the test file ID for
 * mandatory tests.
 */
fun mandatoryTest(id: String): String {
    return "$testFolder/mandatory/oasis_csaf_tc-csaf_2_0-2021-${id}.json"
}

/**
 * Short utility function to construct the path to the test file based on the test file ID for
 * optional tests.
 */
fun optionalTest(id: String): String {
    return "$testFolder/optional/oasis_csaf_tc-csaf_2_0-2021-${id}.json"
}

class TestsTest {
    @Test
    fun test611() {
        val test = Test611MissingDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are not defined: CSAFPID-9080700,CSAFPID-9080701",
            test.test(mandatoryTest("6-1-01-01"))
        )
    }

    @Test
    fun test612() {
        val test = Test612MultipleDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are duplicate: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-02-01"))
        )
    }

    @Test
    fun test613() {
        val test = Test613CircularDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are defined in circles: CSAFPID-9080701",
            test.test(mandatoryTest("6-1-03-01"))
        )
        assertValidationSuccessful(test.test(goodCsaf(productTree = null)))
        assertValidationSuccessful(test.test(goodCsaf(productTree = Csaf.ProductTree())))
    }

    @Test
    fun test614() {
        val test = Test614MissingDefinitionOfProductGroupID

        assertValidationFailed(
            "The following IDs are not defined: CSAFGID-1020301",
            test.test(mandatoryTest("6-1-04-01"))
        )
    }

    @Test
    fun test615() {
        val test = Test615MultipleDefinitionOfProductGroupID

        assertValidationFailed(
            "The following IDs are duplicate: CSAFGID-1020300",
            test.test(mandatoryTest("6-1-05-01"))
        )
    }

    @Test
    fun test616() {
        val test = Test616ContradictingProductStatus

        // failing examples
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-06-01"))
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-06-02"))
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-06-03"))
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700,CSAFPID-9080701",
            test.test(mandatoryTest("6-1-06-04"))
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080702,CSAFPID-9080700,CSAFPID-9080701",
            test.test(mandatoryTest("6-1-06-05"))
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(product_status = null))))
        )
        assertValidationSuccessful(test.test(mandatoryTest("6-1-06-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-06-12")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-06-13")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-06-14")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-06-15")))
    }

    @Test
    fun test617() {
        val test = Test617MultipleScoresWithSameVersionPerProduct

        // failing examples
        assertValidationFailed(
            "The following IDs have multiple scores: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-07-01"))
        )

        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(scores = null))))
        )
        assertValidationSuccessful(test.test(mandatoryTest("6-1-07-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-07-12")))
    }

    @Test
    fun test618() {
        val test = Test618InvalidCVSS

        // failing examples
        assertValidationFailed(
            "Field 'baseSeverity' is required for type with serial name 'io.github.csaf.sbom.schema.generated.Csaf.CvssV3', but it was missing at path: \$.vulnerabilities[0].scores[0].cvss_v3",
            test.test(mandatoryTest("6-1-08-01"))
        )
        assertValidationFailed(
            "Field 'baseSeverity' is required for type with serial name 'io.github.csaf.sbom.schema.generated.Csaf.CvssV3', but it was missing at path: \$.vulnerabilities[0].scores[0].cvss_v3",
            test.test(mandatoryTest("6-1-08-02"))
        )
        assertValidationFailed(
            "Field 'version' is required for type with serial name 'io.github.csaf.sbom.schema.generated.Csaf.CvssV2', but it was missing at path: \$.vulnerabilities[0].scores[0].cvss_v2",
            test.test(mandatoryTest("6-1-08-03"))
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-08-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-08-12")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-08-13")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-08-14")))
    }

    @Test
    fun test619() {
        val test = Test619InvalidCVSSComputation

        // failing examples
        assertValidationFailed(
            "The following properties are invalid: baseScore: 10.0 != 6.5, baseSeverity: LOW != MEDIUM",
            test.test(mandatoryTest("6-1-09-01"))
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
    }

    @Test
    fun test621() {
        val test = Test621UnusedDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are not used: CSAFPID-9080700",
            test.test(optionalTest("6-2-01-01"))
        )
    }

    @Test
    fun testAllGood() {
        val good = goodCsaf()
        val tests = mandatoryTests + optionalTests + informativeTests

        tests.forEach {
            assertEquals(
                ValidationSuccessful,
                it.test(good),
                "${it::class.simpleName} was not successful"
            )
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    @Test
    fun testVersion() {
        @Suppress("USELESS_CAST") assertEquals(null, (null as? JsonObject).version)
        assertEquals(null, JsonObject(content = mapOf()).version)
        assertEquals(null, JsonObject(content = mapOf("version" to JsonPrimitive(null))).version)
        assertEquals("3.0", JsonObject(content = mapOf("version" to JsonPrimitive("3.0"))).version)
    }
}
