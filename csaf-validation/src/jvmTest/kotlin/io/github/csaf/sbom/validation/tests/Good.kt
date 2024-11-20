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

import io.github.csaf.sbom.schema.JsonUri
import io.github.csaf.sbom.schema.epoch
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Tracking
import io.github.csaf.sbom.validation.profiles.InformationalAdvisory
import io.github.csaf.sbom.validation.profiles.SecurityAdvisory
import io.github.csaf.sbom.validation.profiles.SecurityIncidentResponse
import io.github.csaf.sbom.validation.profiles.VEX

fun goodDistribution(label: Csaf.Label? = Csaf.Label.WHITE): Csaf.Distribution {
    return Csaf.Distribution(
        tlp = label?.let { Csaf.Tlp(label = it) },
        text = "can be distributed freely",
    )
}

fun goodPublisher(): Csaf.Publisher =
    Csaf.Publisher(
        category = Csaf.Category1.vendor,
        name = "Test Aggregator",
        namespace = JsonUri("example.com"),
        contact_details = "security@example.com",
        issuing_authority = "Very authoritative",
    )

fun goodTracking(): Tracking =
    Tracking(
        aliases = setOf("alias"),
        generator = Csaf.Generator(engine = Csaf.Engine(name = "csaf-exporter", version = "1.0")),
        current_release_date = epoch(),
        id = "test-title",
        initial_release_date = epoch(),
        revision_history =
            listOf(
                Csaf.RevisionHistory(
                    date = epoch(),
                    number = "1.0.0",
                    summary = "Initial and final release",
                    legacy_version = "1.0"
                )
            ),
        status = Csaf.Status.draft,
        version = "1.0.0",
    )

fun goodNotes() =
    listOf(
        Csaf.Note(
            category = Csaf.Category.description,
            text = "Some Text",
        )
    )

fun goodReferences() =
    listOf(
        Csaf.Reference(
            category = Csaf.Category2.external,
            summary = "Some summary",
            url = JsonUri("https://security.example.com/some-advice"),
        ),
    )

fun goodProductTree(): Csaf.ProductTree =
    Csaf.ProductTree(
        branches =
            listOf(
                Csaf.Branche(
                    category = Csaf.Category3.vendor,
                    name = "Linux Vendor",
                    product =
                        Csaf.Product(
                            name = "Linux",
                            product_id = "linux-all",
                        ),
                    branches =
                        listOf(
                            Csaf.Branche(
                                category = Csaf.Category3.vendor,
                                name = "Linux Vendor",
                                product =
                                    Csaf.Product(
                                        name = "Linux 0.1",
                                        product_id = "linux-0.1",
                                    )
                            ),
                            Csaf.Branche(
                                category = Csaf.Category3.vendor,
                                name = "Linux Vendor",
                                product =
                                    Csaf.Product(
                                        name = "Linux 0.2",
                                        product_id = "linux-0.2",
                                    )
                            ),
                            Csaf.Branche(
                                category = Csaf.Category3.vendor,
                                name = "Linux Vendor",
                                product =
                                    Csaf.Product(
                                        name = "Linux 0.3",
                                        product_id = "linux-0.3",
                                    )
                            ),
                            Csaf.Branche(
                                category = Csaf.Category3.vendor,
                                name = "Linux Vendor",
                                product =
                                    Csaf.Product(
                                        name = "Linux 0.4",
                                        product_id = "linux-0.4",
                                    )
                            ),
                            Csaf.Branche(
                                category = Csaf.Category3.vendor,
                                name = "Linux Vendor",
                                product =
                                    Csaf.Product(
                                        name = "Linux 0.5",
                                        product_id = "linux-0.5",
                                    )
                            )
                        )
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
                            sbom_urls = listOf(JsonUri("https://example.com/sboms/my-product")),
                            skus = listOf("123"),
                            model_numbers = setOf("123"),
                            serial_numbers = setOf("123"),
                            x_generic_uris =
                                listOf(
                                    Csaf.XGenericUri(
                                        namespace = JsonUri("https://example.com"),
                                        uri = JsonUri("https://example.com/my-extension"),
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
                            name = "LinuxProduct",
                            product_id = "linux-product",
                            product_identification_helper = Csaf.ProductIdentificationHelper()
                        ),
                    product_reference = "test-product-name",
                    relates_to_product_reference = "linux-all",
                )
            ),
        product_groups =
            listOf(
                Csaf.ProductGroup(
                    group_id = "some-group",
                    product_ids = setOf("test-product-name", "linux-all", "linux-product"),
                    summary = "Test Group"
                )
            )
    )

fun goodFileHashes(): List<Csaf.FileHashe> {
    return listOf(
        Csaf.FileHashe(value = "21c9a43d22cd02babb34b45a9defb881ae8228f0d034a0779b1321e851cad6a4")
    )
}

fun goodVulnerabilities() =
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
            cwe = null,
            cve = "CVE-1234-4000",
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
                        product_ids = setOf("linux-0.3"),
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
                                confidentialityImpact = Csaf.ConfidentialityImpact.COMPLETE,
                                integrityImpact = Csaf.ConfidentialityImpact.COMPLETE,
                                availabilityImpact = Csaf.ConfidentialityImpact.COMPLETE,
                                exploitability = Csaf.Exploitability.PROOF_OF_CONCEPT,
                                remediationLevel = Csaf.RemediationLevel.OFFICIAL_FIX,
                                reportConfidence = Csaf.ReportConfidence.CONFIRMED,
                                collateralDamagePotential =
                                    Csaf.CollateralDamagePotential.LOW_MEDIUM,
                                targetDistribution = Csaf.TargetDistribution.NOT_DEFINED,
                                confidentialityRequirement =
                                    Csaf.ConfidentialityRequirement.NOT_DEFINED,
                                integrityRequirement = Csaf.ConfidentialityRequirement.NOT_DEFINED,
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
                    first_affected = setOf("linux-0.1"),
                    first_fixed = setOf("linux-0.5"),
                    known_affected = setOf("linux-0.1"),
                    known_not_affected = setOf("linux-0.3"),
                    last_affected = setOf("linux-0.2"),
                    recommended = setOf("linux-0.5"),
                    fixed = setOf("linux-0.5"),
                    under_investigation = setOf("linux-0.4"),
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
                        group_ids = setOf("some-group"),
                        product_ids = setOf("linux-0.1"),
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
                        product_ids = setOf("test-product-name"),
                    )
                )
        )
    )

fun goodCsaf(
    distribution: Csaf.Distribution? = goodDistribution(Csaf.Label.WHITE),
    tracking: Tracking = goodTracking(),
    productTree: Csaf.ProductTree? = goodProductTree(),
    vulnerabilities: List<Csaf.Vulnerability>? = goodVulnerabilities(),
    lang: String? = "en",
    sourceLang: String? = null
): Csaf =
    Csaf(
        document =
            Csaf.Document(
                category = "test",
                csaf_version = "2.0",
                acknowledgments =
                    listOf(
                        Csaf.Acknowledgment(
                            names = listOf("Max Muster"),
                            organization = "Organization",
                            summary = "Some summary",
                            urls = listOf(JsonUri("example.com/ack")),
                        )
                    ),
                lang = lang,
                source_lang = sourceLang,
                publisher = goodPublisher(),
                title = "Test Title",
                distribution = distribution,
                tracking = tracking,
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
                        text = "I don't know that",
                    )
            ),
        product_tree = productTree,
        vulnerabilities = vulnerabilities
    )

fun goodInformationalCsaf(
    notes: List<Csaf.Note>? = goodNotes(),
    references: List<Csaf.Reference>? = goodReferences()
): Csaf {
    return Csaf(
        document =
            Csaf.Document(
                category = InformationalAdvisory.category,
                csaf_version = "2.0",
                publisher = goodPublisher(),
                title = "Some Title",
                tracking = goodTracking(),
                notes = notes,
                references = references,
            )
    )
}

fun goodSecurityIncidentResponseCsaf(references: List<Csaf.Reference>? = goodReferences()): Csaf {
    return Csaf(
        document =
            Csaf.Document(
                category = SecurityIncidentResponse.category,
                csaf_version = "2.0",
                publisher = goodPublisher(),
                title = "Some Title",
                tracking = goodTracking(),
                references = references,
                notes = goodNotes(),
            )
    )
}

fun goodVexCsaf(
    productTree: Csaf.ProductTree? = goodProductTree(),
    vulnerabilities: List<Csaf.Vulnerability>? = goodVulnerabilities()
): Csaf {
    return Csaf(
        document =
            Csaf.Document(
                category = VEX.category,
                csaf_version = "2.0",
                publisher = goodPublisher(),
                title = "Some Title",
                tracking = goodTracking(),
            ),
        product_tree = productTree,
        vulnerabilities = vulnerabilities,
    )
}

fun goodSecurityAdvisoryCsaf(
    productTree: Csaf.ProductTree = goodProductTree(),
    vulnerabilities: List<Csaf.Vulnerability>? = goodVulnerabilities(),
): Csaf {
    return Csaf(
        document =
            Csaf.Document(
                category = SecurityAdvisory.category,
                csaf_version = "2.0",
                publisher = goodPublisher(),
                title = "Some Title",
                tracking = goodTracking(),
            ),
        product_tree = productTree,
        vulnerabilities = vulnerabilities,
    )
}
