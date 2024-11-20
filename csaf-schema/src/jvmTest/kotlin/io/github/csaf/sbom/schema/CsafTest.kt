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
package io.github.csaf.sbom.schema

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Tracking
import kotlin.io.path.Path
import kotlin.io.path.readText
import kotlin.test.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

class CsafTest {

    @Test
    fun testStrict() {
        val file = Path("src/jvmTest/resources/csaf-strict-test.json")
        val ex =
            assertFailsWith<SerializationException> { Json.decodeFromString<Csaf>(file.readText()) }
        val msg = ex.message
        assertNotNull(msg)
        assertTrue(
            msg.contains(
                "Unexpected JSON token at offset 5: Encountered an unknown key 'this_property_does_not_exist' at path"
            )
        )
    }

    @Test
    fun testFailCVSSVector() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                Csaf.CvssV2(
                    version = "2.0",
                    vectorString = "not-a-vector",
                    baseScore = 1.0,
                )
            }
        assertContains(exception.message.toString(), "vectorString does not match pattern")
    }

    @Test
    fun testFailCVE() {
        val exception =
            assertFailsWith<IllegalArgumentException> { Csaf.Vulnerability(cve = "CVE1234") }
        assertContains(
            exception.message.toString(),
            "cve does not match pattern ^CVE-[0-9]{4}-[0-9]{4,}\$"
        )
    }

    @Test
    fun testFailRevisionHistoryLength() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                Tracking(
                    aliases = setOf("this"),
                    current_release_date = epoch(),
                    id = "test-title",
                    initial_release_date = epoch(),
                    revision_history = listOf(),
                    status = Csaf.Status.final,
                    version = "1",
                    generator =
                        Csaf.Generator(
                            engine =
                                Csaf.Engine(
                                    name = "test",
                                    version = "1.0",
                                )
                        )
                )
            }
        assertEquals("revision_history length < minimum 1 - 0", exception.message)
    }

    @Test
    fun testGoodSubBranch() {
        val branch =
            Csaf.Branche(
                branches =
                    listOf(
                        Csaf.Branche(
                            category = Csaf.Category3.vendor,
                            name = "My Sub Vendor",
                        )
                    ),
                category = Csaf.Category3.vendor,
                name = "My Vendor"
            )
        assertNotNull(branch)
    }

    @Test
    fun testCsaf() {
        /* TODO: Currently incomplete because branch coverage seems broken. */
        PojoTestHelper.testAllNew { valGen ->
            assertNotNull(
                Csaf(
                    document =
                        Csaf.Document(
                            category = valGen("test", false),
                            csaf_version = valGen("2.0", false, invalidList = listOf("1.0")),
                            acknowledgments =
                                valGen(
                                    listOf(
                                        Csaf.Acknowledgment(
                                            names =
                                                valGen(
                                                    listOf("Max Muster"),
                                                    invalidList = listOf(listOf(""))
                                                ),
                                            organization = valGen("Organization"),
                                            summary = valGen("Some summary"),
                                            urls = valGen(listOf(JsonUri("example.com/ack"))),
                                        )
                                    )
                                ),
                            lang = valGen("en", invalidList = listOf("00", "loremipsum")),
                            source_lang = valGen("en", invalidList = listOf("00", "loremipsum")),
                            publisher =
                                Csaf.Publisher(
                                    category = Csaf.Category1.vendor,
                                    name = valGen("Test Aggregator", false),
                                    namespace = JsonUri("example.com"),
                                    contact_details = valGen("security@example.com"),
                                    issuing_authority = valGen("Very authoritative"),
                                ),
                            title = valGen("Test Title", false),
                            tracking =
                                Tracking(
                                    aliases =
                                        valGen(setOf("alias"), invalidList = listOf(setOf(""))),
                                    generator =
                                        valGen(
                                            Csaf.Generator(
                                                engine =
                                                    Csaf.Engine(
                                                        name = valGen("csaf-exporter", false),
                                                        version = valGen("1.0")
                                                    )
                                            )
                                        ),
                                    current_release_date = epoch(),
                                    id = valGen("test-title", false),
                                    initial_release_date = epoch(),
                                    revision_history =
                                        valGen(
                                            listOf(
                                                Csaf.RevisionHistory(
                                                    date = epoch(),
                                                    number =
                                                        valGen(
                                                            "1.0.0-alpha1",
                                                            false,
                                                            invalidList = listOf("x", "00")
                                                        ),
                                                    summary =
                                                        valGen("Initial and final release", false),
                                                    legacy_version = valGen("1.0")
                                                )
                                            ),
                                            false
                                        ),
                                    status = Csaf.Status.final,
                                    version =
                                        valGen(
                                            "1.0.0-alpha1",
                                            false,
                                            invalidList = listOf("x", "00")
                                        ),
                                ),
                            distribution =
                                valGen(
                                    Csaf.Distribution(
                                        tlp = valGen(Csaf.Tlp(label = Csaf.Label.WHITE)),
                                        text = valGen("can be distributed freely"),
                                    )
                                ),
                            notes =
                                listOf(
                                    Csaf.Note(
                                        category = Csaf.Category.legal_disclaimer,
                                        text = "Something very legal",
                                        audience = "all",
                                        title = "Disclaimer"
                                    )
                                ),
                            references =
                                listOf(
                                    Csaf.Reference(
                                        summary = "Some document",
                                        url = JsonUri("https://example.com/advisory"),
                                    )
                                ),
                            aggregate_severity =
                                Csaf.AggregateSeverity(
                                    text = valGen("I don't know that", false),
                                )
                        ),
                    product_tree =
                        Csaf.ProductTree(
                            branches =
                                listOf(
                                    Csaf.Branche(
                                        category = Csaf.Category3.vendor,
                                        name = "Test Vendor",
                                    )
                                ),
                            full_product_names =
                                listOf(
                                    Csaf.Product(
                                        name = "Test Product Name",
                                        product_id = "test-product-name",
                                        product_identification_helper =
                                            Csaf.ProductIdentificationHelper(
                                                cpe = "cpe:2.3:o:vendor:product:-:*:*:*:*:*:*:*",
                                                hashes =
                                                    listOf(
                                                        Csaf.Hashe(
                                                            file_hashes =
                                                                listOf(
                                                                    Csaf.FileHashe(
                                                                        value =
                                                                            "fa65e4c5ad0e5f7a94337910847bd10f7af10c74"
                                                                    )
                                                                ),
                                                            filename = "file.txt"
                                                        )
                                                    ),
                                                sbom_urls =
                                                    listOf(
                                                        JsonUri(
                                                            "https://example.com/sboms/my-product"
                                                        )
                                                    ),
                                                skus = listOf("123"),
                                                model_numbers = setOf("123"),
                                                serial_numbers = setOf("123"),
                                                x_generic_uris =
                                                    listOf(
                                                        Csaf.XGenericUri(
                                                            namespace =
                                                                JsonUri("https://example.com"),
                                                            uri =
                                                                JsonUri(
                                                                    "https://example.com/my-extension"
                                                                ),
                                                        )
                                                    ),
                                            )
                                    )
                                ),
                            relationships =
                                listOf(
                                    Csaf.Relationship(
                                        category = Csaf.Category4.installed_on,
                                        full_product_name =
                                            Csaf.Product(
                                                name = "Linux",
                                                product_id = "linux",
                                                product_identification_helper =
                                                    Csaf.ProductIdentificationHelper()
                                            ),
                                        product_reference = "linux",
                                        relates_to_product_reference = "linux"
                                    )
                                ),
                            product_groups =
                                listOf(
                                    Csaf.ProductGroup(
                                        group_id = "test-group-id",
                                        product_ids =
                                            setOf("test-product-name", "test-other-product-name"),
                                        summary = "Test Group"
                                    )
                                )
                        ),
                    vulnerabilities =
                        listOf(
                            Csaf.Vulnerability(
                                acknowledgments =
                                    listOf(
                                        Csaf.Acknowledgment(
                                            names = listOf("hacker-dude"),
                                            organization = "hacker-organization",
                                            summary = "very nice work"
                                        )
                                    ),
                                cwe =
                                    Csaf.Cwe(
                                        id = "CWE-123",
                                        name = "Test Cwe",
                                    ),
                                notes =
                                    listOf(
                                        Csaf.Note(
                                            category = Csaf.Category.description,
                                            text = "This is really bad",
                                        )
                                    ),
                                title = "A serious vulnerability in our product",
                                flags =
                                    setOf(
                                        Csaf.Flag(
                                            date = epoch(),
                                            label = Csaf.Label1.vulnerable_code_not_in_execute_path,
                                            product_ids = setOf("test-product-name"),
                                            group_ids = setOf("test-group-name"),
                                        )
                                    ),
                                ids = setOf(Csaf.Id(system_name = "no-idea", text = "some text")),
                                scores =
                                    listOf(
                                        Csaf.Score(
                                            products = setOf("test-product-name"),
                                            cvss_v2 =
                                                Csaf.CvssV2(
                                                    version = "2.0",
                                                    vectorString = "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                                    baseScore = 9.0,
                                                    accessVector = Csaf.AccessVector.NETWORK,
                                                    accessComplexity = Csaf.AccessComplexity.LOW,
                                                    authentication = Csaf.Authentication.NONE,
                                                    confidentialityImpact =
                                                        Csaf.ConfidentialityImpact.COMPLETE,
                                                    integrityImpact =
                                                        Csaf.ConfidentialityImpact.COMPLETE,
                                                    availabilityImpact =
                                                        Csaf.ConfidentialityImpact.COMPLETE,
                                                    exploitability =
                                                        Csaf.Exploitability.PROOF_OF_CONCEPT,
                                                    remediationLevel =
                                                        Csaf.RemediationLevel.OFFICIAL_FIX,
                                                    reportConfidence =
                                                        Csaf.ReportConfidence.CONFIRMED,
                                                    collateralDamagePotential =
                                                        Csaf.CollateralDamagePotential.LOW_MEDIUM,
                                                    targetDistribution =
                                                        Csaf.TargetDistribution.NOT_DEFINED,
                                                    confidentialityRequirement =
                                                        Csaf.ConfidentialityRequirement.NOT_DEFINED,
                                                    integrityRequirement =
                                                        Csaf.ConfidentialityRequirement.NOT_DEFINED,
                                                    availabilityRequirement =
                                                        Csaf.ConfidentialityRequirement.NOT_DEFINED,
                                                    temporalScore = 9.0,
                                                    environmentalScore = 9.0,
                                                )
                                        )
                                    ),
                                involvements =
                                    setOf(
                                        Csaf.Involvement(
                                            party = Csaf.Party.vendor,
                                            summary = "We are the vendor",
                                            status = Csaf.Status1.completed
                                        )
                                    ),
                                product_status =
                                    Csaf.ProductStatus(
                                        first_affected = setOf("0.1"),
                                        first_fixed = setOf("0.1", "0.2"),
                                        known_affected = setOf("0.1", "0.3"),
                                        known_not_affected = setOf("0.1", "0.4"),
                                        last_affected = setOf("0.1", "0.2"),
                                        recommended = setOf("0.1", "0.3"),
                                        fixed = setOf("0.1", "0.4"),
                                        under_investigation = setOf("0.1", "0.3"),
                                    ),
                                remediations =
                                    listOf(
                                        Csaf.Remediation(
                                            category = Csaf.Category5.vendor_fix,
                                            details = "We fixed it. Just update",
                                            restart_required =
                                                Csaf.RestartRequired(
                                                    category = Csaf.Category6.machine,
                                                    details = "just restart your machine"
                                                ),
                                            group_ids = setOf("test-group-id"),
                                            product_ids =
                                                setOf(
                                                    "test-product-name",
                                                    "test-other-product-name"
                                                ),
                                            entitlements = listOf("not-sure-what-this-is"),
                                        )
                                    ),
                                references =
                                    listOf(
                                        Csaf.Reference(
                                            category = Csaf.Category2.external,
                                            summary = "Additional reference",
                                            url = JsonUri("https://example.com/reference")
                                        )
                                    ),
                                threats =
                                    listOf(
                                        Csaf.Threat(
                                            category = Csaf.Category7.exploit_status,
                                            details = "Can be used to exploit something",
                                            group_ids = setOf("some-group"),
                                            product_ids = setOf("some-product"),
                                        )
                                    )
                            )
                        )
                )
            )
        }
    }
}
