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

import io.github.csaf.sbom.generated.Csaf
import io.github.csaf.sbom.generated.Csaf.Tracking
import java.math.BigDecimal
import java.net.URI
import java.time.OffsetDateTime
import kotlin.test.*

class CsafTest {

    @Test
    fun testFailCVSSVector() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                Csaf.CvssV2(
                    version = "2.0",
                    vectorString = "not-a-vector",
                    baseScore = BigDecimal.ONE,
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
                    current_release_date = OffsetDateTime.now(),
                    id = "test-title",
                    initial_release_date = OffsetDateTime.now(),
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
    fun testGoodDocument() {
        val doc =
            Csaf(
                document =
                    Csaf.Document(
                        category = "test",
                        csaf_version = "2.0",
                        acknowledgments =
                            listOf(
                                Csaf.Acknowledgment(
                                    urls = listOf(URI("example.com/ack")),
                                )
                            ),
                        lang = "en",
                        source_lang = "en",
                        publisher =
                            Csaf.Publisher(
                                category = Csaf.Category1.vendor,
                                name = "Test Aggregator",
                                namespace = URI("example.com"),
                                contact_details = "security@example.com",
                                issuing_authority = "Very authoritative",
                            ),
                        title = "Test Title",
                        tracking =
                            Tracking(
                                current_release_date = OffsetDateTime.now(),
                                id = "test-title",
                                initial_release_date = OffsetDateTime.now(),
                                revision_history =
                                    listOf(
                                        Csaf.RevisionHistory(
                                            date = OffsetDateTime.now(),
                                            number = "1",
                                            summary = "Initial and final release",
                                            legacy_version = "1.0"
                                        )
                                    ),
                                status = Csaf.Status.final,
                                version = "1",
                            ),
                        distribution =
                            Csaf.Distribution(
                                tlp =
                                    Csaf.Tlp(
                                        label = Csaf.Label.WHITE,
                                    ),
                                text = "can be distributed freely",
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
                                    url = URI("https://example.com/advisory"),
                                )
                            ),
                        aggregate_severity =
                            Csaf.AggregateSeverity(
                                text = "I don't know that",
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
                                                listOf(URI("https://example.com/sboms/my-product")),
                                            skus = listOf("123"),
                                            model_numbers = setOf("123"),
                                            serial_numbers = setOf("123"),
                                            x_generic_uris =
                                                listOf(
                                                    Csaf.XGenericUri(
                                                        namespace = URI("https://example.com"),
                                                        uri =
                                                            URI("https://example.com/my-extension"),
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
                                        date = OffsetDateTime.now(),
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
                                                baseScore = BigDecimal.valueOf(9.0),
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
                                                reportConfidence = Csaf.ReportConfidence.CONFIRMED,
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
                                                temporalScore = BigDecimal.valueOf(9.0),
                                                environmentalScore = BigDecimal.valueOf(9.0),
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
                                            setOf("test-product-name", "test-other-product-name"),
                                        entitlements = listOf("not-sure-what-this-is"),
                                    )
                                ),
                            references =
                                listOf(
                                    Csaf.Reference(
                                        category = Csaf.Category2.external,
                                        summary = "Additional reference",
                                        url = URI("https://example.com/reference")
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
        assertNotNull(doc)
    }
}
