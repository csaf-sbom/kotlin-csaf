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
package io.csaf.validation.tests

import io.csaf.schema.JsonUri
import io.csaf.schema.epoch
import io.csaf.schema.generated.Csaf
import io.csaf.validation.ValidationSuccessful
import io.csaf.validation.assertValidationFailed
import io.csaf.validation.assertValidationSuccessful
import io.csaf.validation.generated.Testcases
import kotlin.io.path.Path
import kotlin.io.path.readText
import kotlin.test.*
import kotlinx.serialization.json.Json

/** The path to the test folder for the CSAF 2.0 tests. */
var testFolder: String = "../csaf/csaf_2.0/test/validator/data/"

class TestsTest {

    val executedTests = mutableSetOf<String>()

    companion object {
        val jsonBuilder = Json { ignoreUnknownKeys = true }
        val testCases =
            jsonBuilder.decodeFromString<Testcases>(Path("$testFolder/testcases.json").readText())
    }

    @AfterTest
    fun checkAllTestCases() {
        val firstExecuted = executedTests.firstOrNull()
        // Nothing to do, special case for testAllGood
        if (firstExecuted == null) {
            return
        }

        // Try to find the test
        val test =
            testCases.tests.firstOrNull {
                (it.valid + it.failures).any { it.name == firstExecuted }
            }
        assertNotNull(test)

        val allTestPaths = (test.valid + test.failures).map { it.name }
        val missing = allTestPaths - allTestPaths.intersect(executedTests)

        assertTrue(
            missing.isEmpty(),
            "The following test cases were not included in the unit test: ${missing.joinToString(", ")}",
        )
    }

    @Test
    fun test611() {
        val test = Test611MissingDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are not defined: CSAFPID-9080700,CSAFPID-9080701",
            test.test(mandatoryTest("6-1-01-01")),
        )
    }

    @Test
    fun test612() {
        val test = Test612MultipleDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are duplicate: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-02-01")),
        )
    }

    @Test
    fun test613() {
        val test = Test613CircularDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are defined in circles: CSAFPID-9080701",
            test.test(mandatoryTest("6-1-03-01")),
        )
        assertValidationSuccessful(test.test(goodCsaf(productTree = null)))
        assertValidationSuccessful(test.test(goodCsaf(productTree = Csaf.ProductTree())))
    }

    @Test
    fun test614() {
        val test = Test614MissingDefinitionOfProductGroupID

        assertValidationFailed(
            "The following IDs are not defined: CSAFGID-1020301",
            test.test(mandatoryTest("6-1-04-01")),
        )
    }

    @Test
    fun test615() {
        val test = Test615MultipleDefinitionOfProductGroupID

        assertValidationFailed(
            "The following IDs are duplicate: CSAFGID-1020300",
            test.test(mandatoryTest("6-1-05-01")),
        )
    }

    @Test
    fun test616() {
        val test = Test616ContradictingProductStatus

        // failing examples
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-06-01")),
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-06-02")),
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-06-03")),
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080700,CSAFPID-9080701",
            test.test(mandatoryTest("6-1-06-04")),
        )
        assertValidationFailed(
            "The following IDs have contradicting statuses: CSAFPID-9080702,CSAFPID-9080700,CSAFPID-9080701",
            test.test(mandatoryTest("6-1-06-05")),
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
            test.test(mandatoryTest("6-1-07-01")),
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
            "Field 'baseSeverity' is required for type with serial name 'io.csaf.schema.generated.Csaf.CvssV3', but it was missing at path: \$.vulnerabilities[0].scores[0].cvss_v3",
            test.test(mandatoryTest("6-1-08-01")),
        )
        assertValidationFailed(
            "Field 'baseSeverity' is required for type with serial name 'io.csaf.schema.generated.Csaf.CvssV3', but it was missing at path: \$.vulnerabilities[0].scores[0].cvss_v3",
            test.test(mandatoryTest("6-1-08-02")),
        )
        assertValidationFailed(
            "Field 'version' is required for type with serial name 'io.csaf.schema.generated.Csaf.CvssV2', but it was missing at path: \$.vulnerabilities[0].scores[0].cvss_v2",
            test.test(mandatoryTest("6-1-08-03")),
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
            test.test(mandatoryTest("6-1-09-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(scores = null))))
        )
    }

    @Test
    fun test6110() {
        val test = Test6110InconsistentCVSS

        // failing examples
        assertValidationFailed(
            "The following properties are inconsistent: attackVector: LOCAL != NETWORK, scope: CHANGED != UNCHANGED, availabilityImpact: LOW != HIGH",
            test.test(mandatoryTest("6-1-10-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(scores = null))))
        )
    }

    @Test
    fun test6111() {
        val test = Test6111CWE

        // failing examples
        assertValidationFailed(
            "Invalid CWE entries: Improper Input Validation is not the correct name for CWE-79",
            test.test(mandatoryTest("6-1-11-01")),
        )
        assertValidationFailed(
            "Invalid CWE entries: CWE-12345 is invalid",
            test.test(
                goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(cwe = Csaf.Cwe(id = "CWE-12345", name = "Some name"))
                        )
                )
            ),
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(cwe = null))))
        )
        assertValidationSuccessful(
            test.test(
                goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                cwe =
                                    Csaf.Cwe(
                                        id = "CWE-79",
                                        name =
                                            "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                                    )
                            )
                        )
                )
            )
        )
    }

    @Test
    fun test6112() {
        val test = Test6112Language

        // failing examples
        assertValidationFailed(
            "The following languages are not valid: EZ",
            test.test(mandatoryTest("6-1-12-01")),
        )
        assertValidationFailed(
            "The following languages are not valid: EZ",
            (test.test(goodCsaf(sourceLang = "EZ"))),
        )
        assertValidationFailed(
            "The following languages are not valid: EN-ezzz",
            (test.test(goodCsaf(sourceLang = "EN-ezzz"))),
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf(lang = null)))
        assertValidationSuccessful(test.test(goodCsaf(sourceLang = "en")))
        assertValidationSuccessful(test.test(goodCsaf(sourceLang = "en-US")))
    }

    @Test
    fun test6113() {
        val test = Test6113PURL

        // failing examples
        assertValidationFailed(
            "Invalid PURLs: The PackageURL name specified is invalid",
            test.test(mandatoryTest("6-1-13-01")),
        )

        // good examples
        assertValidationSuccessful(
            test.test(
                goodCsaf(
                    productTree =
                        Csaf.ProductTree(
                            full_product_names =
                                listOf(
                                    Csaf.Product(
                                        name = "My Product",
                                        product_id = "product1",
                                        product_identification_helper =
                                            Csaf.ProductIdentificationHelper(
                                                purl =
                                                    JsonUri(
                                                        "pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c"
                                                    )
                                            ),
                                    )
                                )
                        )
                )
            )
        )
    }

    @Test
    fun test6114() {
        val test = Test6114SortedRevisionHistory

        // failing examples
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-01")),
        )
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-02")),
        )
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-03")),
        )
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-04")),
        )
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-05")),
        )
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-06")),
        )
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-07")),
        )
        assertValidationFailed(
            "The revision history is not sorted by ascending date",
            test.test(mandatoryTest("6-1-14-08")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-12")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-13")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-14")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-15")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-16")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-17")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-18")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-14-19")))
    }

    @Test
    fun test6115() {
        val test = Test6115Translator

        // failing examples
        assertValidationFailed(
            "The publisher is a translator, but the source language is not present",
            test.test(mandatoryTest("6-1-15-01")),
        )
        assertValidationFailed(
            "The publisher is a translator, but the source language is not present",
            test.test(mandatoryTest("6-1-15-02")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-15-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-15-12")))
    }

    @Test
    fun test6116() {
        val test = Test6116LatestDocumentVersion

        // failing examples
        assertValidationFailed(
            "The latest version should be 2 but is 1",
            test.test(mandatoryTest("6-1-16-01")),
        )
        assertValidationFailed(
            "The latest version should be 2 but is 1",
            test.test(mandatoryTest("6-1-16-02")),
        )
        assertValidationFailed(
            "The latest version should be 2 but is 1",
            test.test(mandatoryTest("6-1-16-03")),
        )
        assertValidationFailed(
            "The latest version should be 2.0.0 but is 1.0.0",
            test.test(mandatoryTest("6-1-16-04")),
        )
        assertValidationFailed(
            "The latest version should be 2.0.0 but is 1.0.0",
            test.test(mandatoryTest("6-1-16-05")),
        )
        assertValidationFailed(
            "The latest version should be 10 but is 9",
            test.test(mandatoryTest("6-1-16-06")),
        )
        assertValidationFailed(
            "The latest version should be 1.10.0 but is 1.9.0",
            test.test(mandatoryTest("6-1-16-07")),
        )
        assertValidationFailed(
            "The latest version should be 2 but is 1",
            test.test(mandatoryTest("6-1-16-08")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-12")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-13")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-14")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-15")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-16")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-17")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-18")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-19")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-16-31")))
    }

    @Test
    fun test6117() {
        val test = Test6117DocumentStatusDraft

        // failing examples
        assertValidationFailed(
            "The latest version is a pre-release or \"zero\" version (0.9.5) but the document status is final",
            test.test(mandatoryTest("6-1-17-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf()))
        assertValidationSuccessful(
            test.test(
                Csaf(
                    document =
                        Csaf.Document(
                            tracking =
                                Csaf.Tracking(
                                    current_release_date = epoch(),
                                    version = "1.2.0-alpha1",
                                    id = "test",
                                    initial_release_date = epoch(),
                                    revision_history =
                                        listOf(
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "1.2.0-alpha1",
                                                summary = "test",
                                            )
                                        ),
                                    status = Csaf.Status.draft,
                                ),
                            category = "csaf_base",
                            csaf_version = "2.0",
                            publisher =
                                Csaf.Publisher(
                                    category = Csaf.Category1.vendor,
                                    name = "My Publisher",
                                    namespace = JsonUri("https://example.com"),
                                ),
                            title = "My Title",
                        )
                )
            )
        )
        assertValidationSuccessful(
            test.test(
                Csaf(
                    document =
                        Csaf.Document(
                            tracking =
                                Csaf.Tracking(
                                    current_release_date = epoch(),
                                    version = "0",
                                    id = "test",
                                    initial_release_date = epoch(),
                                    revision_history =
                                        listOf(
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "0",
                                                summary = "test",
                                            )
                                        ),
                                    status = Csaf.Status.draft,
                                ),
                            category = "csaf_base",
                            csaf_version = "2.0",
                            publisher =
                                Csaf.Publisher(
                                    category = Csaf.Category1.vendor,
                                    name = "My Publisher",
                                    namespace = JsonUri("https://example.com"),
                                ),
                            title = "My Title",
                        )
                )
            )
        )
    }

    @Test
    fun test6118() {
        val test = Test6118ReleasedRevisionHistory

        // failing examples
        assertValidationFailed(
            "The document is final but it contains the following revisions: 0",
            test.test(mandatoryTest("6-1-18-01")),
        )
        assertValidationFailed(
            "The document is final but it contains the following revisions: 0.9.0",
            test.test(
                Csaf(
                    document =
                        Csaf.Document(
                            tracking =
                                Csaf.Tracking(
                                    current_release_date = epoch(),
                                    version = "1.0.0",
                                    id = "test",
                                    initial_release_date = epoch(),
                                    revision_history =
                                        listOf(
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "0.9.0",
                                                summary = "test",
                                            ),
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "1.0.0",
                                                summary = "test",
                                            ),
                                        ),
                                    status = Csaf.Status.final,
                                ),
                            category = "csaf_base",
                            csaf_version = "2.0",
                            publisher =
                                Csaf.Publisher(
                                    category = Csaf.Category1.vendor,
                                    name = "My Publisher",
                                    namespace = JsonUri("https://example.com"),
                                ),
                            title = "My Title",
                        )
                )
            ),
        )

        // good examples
        assertValidationSuccessful(
            test.test(
                Csaf(
                    document =
                        Csaf.Document(
                            tracking =
                                Csaf.Tracking(
                                    current_release_date = epoch(),
                                    version = "1",
                                    id = "test",
                                    initial_release_date = epoch(),
                                    revision_history =
                                        listOf(
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "1",
                                                summary = "test",
                                            ),
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "1.0.0",
                                                summary = "test",
                                            ),
                                        ),
                                    status = Csaf.Status.final,
                                ),
                            category = "csaf_base",
                            csaf_version = "2.0",
                            publisher =
                                Csaf.Publisher(
                                    category = Csaf.Category1.vendor,
                                    name = "My Publisher",
                                    namespace = JsonUri("https://example.com"),
                                ),
                            title = "My Title",
                        )
                )
            )
        )
    }

    @Test
    fun test6119() {
        val test = Test6119RevisionHistoryEntriesForPreReleaseVersions

        // failing examples
        assertValidationFailed(
            "The document contains the following pre-release revisions: 1.0.0-rc",
            test.test(mandatoryTest("6-1-19-01")),
        )
        assertValidationFailed(
            "The document contains the following pre-release revisions: 1.0.0-rc",
            test.test(mandatoryTest("6-1-19-02")),
        )

        // good examples
        assertValidationSuccessful(
            test.test(
                Csaf(
                    document =
                        Csaf.Document(
                            tracking =
                                Csaf.Tracking(
                                    current_release_date = epoch(),
                                    version = "1",
                                    id = "test",
                                    initial_release_date = epoch(),
                                    revision_history =
                                        listOf(
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "1",
                                                summary = "test",
                                            ),
                                            Csaf.RevisionHistory(
                                                date = epoch(),
                                                number = "1.0.0",
                                                summary = "test",
                                            ),
                                        ),
                                    status = Csaf.Status.final,
                                ),
                            category = "csaf_base",
                            csaf_version = "2.0",
                            publisher =
                                Csaf.Publisher(
                                    category = Csaf.Category1.vendor,
                                    name = "My Publisher",
                                    namespace = JsonUri("https://example.com"),
                                ),
                            title = "My Title",
                        )
                )
            )
        )
    }

    @Test
    fun test6120() {
        val test = Test6120NonDraftDocumentVersion

        // failing examples
        assertValidationFailed(
            "The latest version is a pre-release (1.0.0-alpha) but the document status is interim",
            test.test(mandatoryTest("6-1-20-01")),
        )
    }

    @Test
    fun test6121() {
        val test = Test6121MissingItemInRevisionHistory

        // failing examples
        assertValidationFailed(
            "The following versions are missing: 2",
            test.test(mandatoryTest("6-1-21-01")),
        )
        assertValidationFailed(
            "Start version 2 must be either 0 or 1 (or a major version of it)",
            test.test(mandatoryTest("6-1-21-02")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-21-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-21-12")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-21-13")))
    }

    @Test
    fun test6122() {
        val test = Test6122MultipleDefinitionInRevisionHistory

        // failing examples
        assertValidationFailed(
            "The following versions in the revision history are duplicate: 1",
            test.test(mandatoryTest("6-1-22-01")),
        )
    }

    @Test
    fun test6123() {
        val test = Test6123MultipleUseOfSameCVE

        // failing examples
        assertValidationFailed(
            "The following CVE identifiers are duplicate: CVE-2017-0145",
            test.test(mandatoryTest("6-1-23-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
    }

    @Test
    fun test6124() {
        val test = Test6124MultipleDefinitionInInvolvements

        // failing examples
        assertValidationFailed(
            "The following party/date pairs are duplicate: (vendor, 2021-04-23T10:00:00Z)",
            test.test(mandatoryTest("6-1-24-01")),
        )
        assertValidationFailed(
            "The following party/date pairs are duplicate: (vendor, 2021-04-23T10:00:00Z)",
            test.test(mandatoryTest("6-1-24-02")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-24-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-24-12")))
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
    }

    @Test
    fun test6125() {
        val test = Test6125MultipleUseOfSameHashAlgorithm

        // failing examples
        assertValidationFailed(
            "The following hash algorithms are duplicate: sha256",
            test.test(mandatoryTest("6-1-25-01")),
        )
    }

    @Test
    fun test6126() {
        val test = Test6126ProhibitedDocumentCategoryName

        // failing examples
        assertValidationFailed(
            "The value Security_Incident_Response conflicts with the name of an official profile",
            test.test(mandatoryTest("6-1-26-01")),
        )
    }

    @Test
    fun test61271() {
        val test = Test61271DocumentNotes

        // failing examples
        assertValidationFailed(
            "The document notes do not contain an item which has a category of description, details, general or summary",
            test.test(mandatoryTest("6-1-27-01-01")),
        )
        assertValidationFailed(
            "The document notes do not contain an item which has a category of description, details, general or summary",
            test.test(goodInformationalCsaf(notes = null)),
        )
    }

    @Test
    fun test61272() {
        val test = Test61272DocumentReferences

        // failing examples
        assertValidationFailed(
            "The document references do not contain any item which has the category external",
            test.test(mandatoryTest("6-1-27-02-01")),
        )
        assertValidationFailed(
            "The document references do not contain any item which has the category external",
            test.test(goodInformationalCsaf(references = null)),
        )
        assertValidationFailed(
            "The document references do not contain any item which has the category external",
            test.test(goodSecurityIncidentResponseCsaf(references = null)),
        )

        // good examples
        assertValidationSuccessful(test.test(goodVexCsaf()))
    }

    @Test
    fun test61273() {
        val test = Test61273Vulnerabilities

        // failing examples
        assertValidationFailed(
            "The element /vulnerabilities exists",
            test.test(mandatoryTest("6-1-27-03-01")),
        )
    }

    @Test
    fun test61274() {
        val test = Test61274ProductTree

        // failing examples
        assertValidationFailed(
            "The element /product_tree does not exist",
            test.test(mandatoryTest("6-1-27-04-01")),
        )
    }

    @Test
    fun test61275() {
        val test = Test61275VulnerabilityNotes

        // failing examples
        assertValidationFailed(
            "The vulnerability item has no notes element",
            test.test(mandatoryTest("6-1-27-05-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(goodVexCsaf(vulnerabilities = null)))
    }

    @Test
    fun test61276() {
        val test = Test61276ProductStatus

        // failing examples
        assertValidationFailed(
            "The vulnerability item has no product_status element",
            test.test(mandatoryTest("6-1-27-06-01")),
        )
        assertValidationSuccessful(test.test(goodSecurityAdvisoryCsaf(vulnerabilities = null)))
    }

    @Test
    fun test61277() {
        val test = Test61277VEXProductStatus

        // failing examples
        assertValidationFailed(
            "None of the elements fixed, known_affected, known_not_affected, or under_investigation is present in product_status",
            test.test(mandatoryTest("6-1-27-07-01")),
        )
        assertValidationFailed(
            "None of the elements fixed, known_affected, known_not_affected, or under_investigation is present in product_status",
            test.test(
                goodVexCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                product_status =
                                    Csaf.ProductStatus(
                                        fixed = null,
                                        known_affected = null,
                                        known_not_affected = null,
                                        under_investigation = null,
                                    )
                            )
                        )
                )
            ),
        )
        assertValidationFailed(
            "None of the elements fixed, known_affected, known_not_affected, or under_investigation is present in product_status",
            test.test(
                goodVexCsaf(vulnerabilities = listOf(Csaf.Vulnerability(product_status = null)))
            ),
        )

        // good examples
        assertValidationSuccessful(test.test(goodVexCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(
                goodVexCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                product_status =
                                    Csaf.ProductStatus(
                                        fixed = setOf("fixed"),
                                        known_affected = null,
                                        known_not_affected = null,
                                        under_investigation = null,
                                    )
                            )
                        )
                )
            )
        )
        assertValidationSuccessful(
            test.test(
                goodVexCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                product_status =
                                    Csaf.ProductStatus(
                                        fixed = null,
                                        known_affected = setOf("fixed"),
                                        known_not_affected = null,
                                        under_investigation = null,
                                    )
                            )
                        )
                )
            )
        )
        assertValidationSuccessful(
            test.test(
                goodVexCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                product_status =
                                    Csaf.ProductStatus(
                                        fixed = null,
                                        known_affected = null,
                                        known_not_affected = setOf("fixed"),
                                        under_investigation = null,
                                    )
                            )
                        )
                )
            )
        )
        assertValidationSuccessful(
            test.test(
                goodVexCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                product_status =
                                    Csaf.ProductStatus(
                                        fixed = null,
                                        known_affected = null,
                                        known_not_affected = null,
                                        under_investigation = setOf("fixed"),
                                    )
                            )
                        )
                )
            )
        )
    }

    @Test
    fun test61278() {
        val test = Test61278VulnerabilityID

        // failing examples
        assertValidationFailed(
            "None of the elements cve or ids is present",
            test.test(mandatoryTest("6-1-27-08-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(goodVexCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(
                goodVexCsaf(
                    vulnerabilities = listOf(Csaf.Vulnerability(ids = null, cve = "CVE-1234-5000"))
                )
            )
        )
        assertValidationSuccessful(
            test.test(
                goodVexCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                ids = setOf(Csaf.Id(system_name = "what", text = "is this")),
                                cve = null,
                            )
                        )
                )
            )
        )
    }

    @Test
    fun test61279() {
        val test = Test61279ImpactStatement

        // failing examples
        assertValidationFailed(
            "Missing impact statement for product IDs: CSAFPID-9080702",
            test.test(mandatoryTest("6-1-27-09-01")),
        )
        assertValidationFailed(
            "Missing impact statement for product IDs: CSAFPID-9080702",
            test.test(mandatoryTest("6-1-27-09-02")),
        )
        assertValidationFailed(
            "Missing impact statement for product IDs: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-27-09-03")),
        )
        assertValidationFailed(
            "Missing impact statement for product IDs: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-27-09-04")),
        )
        assertValidationFailed(
            "Missing impact statement for product IDs: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-27-09-05")),
        )
        assertValidationFailed(
            "Missing impact statement for product IDs: CSAFPID-9080701",
            test.test(mandatoryTest("6-1-27-09-06")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-27-09-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-27-09-12")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-27-09-13")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-27-09-14")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-27-09-15")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-27-09-16")))
        assertValidationSuccessful(test.test(goodVexCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(goodVexCsaf(vulnerabilities = listOf(Csaf.Vulnerability(threats = null))))
        )
    }

    @Test
    fun test612710() {
        val test = Test612710ActionStatement

        // failing examples
        assertValidationFailed(
            "Missing action statement for product IDs: CSAFPID-9080702",
            test.test(mandatoryTest("6-1-27-10-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(goodVexCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(
                goodVexCsaf(vulnerabilities = listOf(Csaf.Vulnerability(remediations = null)))
            )
        )
    }

    @Test
    fun test612711() {
        val test = Test612711Vulnerabilities

        // failing examples
        assertValidationFailed(
            "The element /vulnerabilities does not exist",
            test.test(mandatoryTest("6-1-27-11-01")),
        )
    }

    @Test
    fun test6128() {
        val test = Test6128Translation

        // failing examples
        assertValidationFailed(
            "The document language and the source language have the same value: en-US",
            test.test(mandatoryTest("6-1-28-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-28-11")))
    }

    @Test
    fun test6129() {
        val test = Test6129RemediationWithoutProductReference

        // failing examples
        assertValidationFailed(
            "The given remediation does not specify to which products it should be applied",
            test.test(mandatoryTest("6-1-29-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-29-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-29-12")))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(remediations = null))))
        )
        assertValidationSuccessful(
            test.test(
                goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                remediations =
                                    listOf(
                                        Csaf.Remediation(
                                            category = Csaf.Category5.vendor_fix,
                                            details = "test",
                                            product_ids = null,
                                            group_ids = setOf("group1"),
                                        )
                                    )
                            )
                        )
                )
            )
        )
        assertValidationSuccessful(
            test.test(
                goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                remediations =
                                    listOf(
                                        Csaf.Remediation(
                                            category = Csaf.Category5.vendor_fix,
                                            details = "test",
                                            product_ids = setOf("product1"),
                                            group_ids = null,
                                        )
                                    )
                            )
                        )
                )
            )
        )
    }

    @Test
    fun test6130() {
        val test = Test6130MixedIntegerAndSemanticVersioning

        // failing examples
        assertValidationFailed(
            "The following versions are invalid because of a mix of integer and semantic versioning: 2, 2",
            test.test(mandatoryTest("6-1-30-01")),
        )
        assertValidationFailed(
            "The following versions are invalid because of a mix of integer and semantic versioning: 1.0.0",
            test.test(
                goodCsaf(
                    tracking =
                        Csaf.Tracking(
                            revision_history =
                                listOf(
                                    Csaf.RevisionHistory(
                                        date = epoch(),
                                        number = "2",
                                        summary = "test",
                                    )
                                ),
                            current_release_date = epoch(),
                            id = "test",
                            initial_release_date = epoch(),
                            status = Csaf.Status.final,
                            version = "1.0.0",
                        )
                )
            ),
        )
        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-30-11")))
    }

    @Test
    fun test6131() {
        val test = Test6131VersionRangeInProductVersion

        // failing examples
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: prior to 4.2",
            test.test(mandatoryTest("6-1-31-01")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: <4.2",
            test.test(mandatoryTest("6-1-31-02")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: <=4.1",
            test.test(mandatoryTest("6-1-31-03")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: <= 4.1",
            test.test(mandatoryTest("6-1-31-04")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: 4.1 and earlier",
            test.test(mandatoryTest("6-1-31-05")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: all",
            test.test(mandatoryTest("6-1-31-06")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: before 4.2",
            test.test(mandatoryTest("6-1-31-07")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: 4.2 and later",
            test.test(mandatoryTest("6-1-31-08")),
        )
        assertValidationFailed(
            "The following product versions are invalid and contain version ranges: 3.X versions",
            test.test(mandatoryTest("6-1-31-09")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-31-11")))
        assertValidationSuccessful(test.test(mandatoryTest("6-1-31-12")))
        assertValidationSuccessful(test.test(goodCsaf(productTree = null)))
    }

    @Test
    fun test6132() {
        val test = Test6132FlagWithoutProductReference

        // failing examples
        assertValidationFailed(
            "The following flags are missing products or groups: component_not_present",
            test.test(mandatoryTest("6-1-32-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-32-11")))
        assertValidationSuccessful(test.test(goodCsaf(vulnerabilities = null)))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(flags = null))))
        )
        assertValidationSuccessful(
            test.test(
                goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                flags =
                                    setOf(
                                        Csaf.Flag(
                                            date = epoch(),
                                            group_ids = setOf("group1"),
                                            label = Csaf.Label1.component_not_present,
                                            product_ids = null,
                                        )
                                    )
                            )
                        )
                )
            )
        )
        assertValidationSuccessful(
            test.test(
                goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                flags =
                                    setOf(
                                        Csaf.Flag(
                                            date = epoch(),
                                            group_ids = null,
                                            label = Csaf.Label1.component_not_present,
                                            product_ids = setOf("product1"),
                                        )
                                    )
                            )
                        )
                )
            )
        )
    }

    @Test
    fun test6133() {
        val test = Test6133MultipleFlagsWithVEXJustificationCodesPerProduct

        // failing examples
        assertValidationFailed(
            "The following product IDs are part of multiple flags: CSAFPID-9080700",
            test.test(mandatoryTest("6-1-33-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(mandatoryTest("6-1-33-11")))
        assertValidationSuccessful(
            test.test(goodCsaf(vulnerabilities = listOf(Csaf.Vulnerability(flags = null))))
        )
        assertValidationSuccessful(
            test.test(
                goodCsaf(
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                flags =
                                    setOf(
                                        Csaf.Flag(
                                            label = Csaf.Label1.component_not_present,
                                            product_ids = null,
                                            group_ids = null,
                                        )
                                    )
                            )
                        )
                )
            )
        )
    }

    @Test
    fun test621() {
        val test = Test621UnusedDefinitionOfProductID

        assertValidationFailed(
            "The following IDs are not used: CSAFPID-9080700",
            test.test(optionalTest("6-2-01-01")),
        )

        // good examples
        assertValidationSuccessful(test.test(optionalTest("6-2-01-11")))
    }

    @Test
    fun testAllGood() {
        val goods =
            listOf(
                goodCsaf(),
                goodInformationalCsaf(),
                goodVexCsaf(),
                goodSecurityAdvisoryCsaf(),
                goodSecurityIncidentResponseCsaf(),
            )
        val tests = mandatoryTests + optionalTests + informativeTests

        goods.forEach { good ->
            tests.forEach {
                assertEquals(
                    ValidationSuccessful,
                    it.test(good),
                    "${it::class.simpleName} was not successful",
                )
            }
        }
    }

    @Test
    fun `notAffectedProducts returns correct set of product IDs`() {
        val productStatus =
            Csaf.ProductStatus(
                known_not_affected = setOf("prod1"),
                first_fixed = setOf("prod2"),
                fixed = setOf("prod3"),
                recommended = setOf("prod4"),
            )
        val vuln = Csaf.Vulnerability(product_status = productStatus)
        val result = vuln.notAffectedProducts
        assertEquals(setOf("prod1", "prod2", "prod3", "prod4"), result)
    }

    @Test
    fun `notAffectedProducts returns empty set when product_status is null`() {
        val vuln = Csaf.Vulnerability(product_status = null)
        val result = vuln.notAffectedProducts
        assertEquals(emptySet(), result)
    }

    /**
     * Short utility function to construct the path to the test file based on the test file ID for
     * mandatory tests.
     */
    private fun mandatoryTest(id: String): String {
        val test = "mandatory/oasis_csaf_tc-csaf_2_0-2021-${id}.json"
        executedTests += test

        return "$testFolder/$test"
    }

    /**
     * Short utility function to construct the path to the test file based on the test file ID for
     * optional tests.
     */
    private fun optionalTest(id: String): String {
        val test = "optional/oasis_csaf_tc-csaf_2_0-2021-${id}.json"
        executedTests += test

        return "$testFolder/$test"
    }
}
