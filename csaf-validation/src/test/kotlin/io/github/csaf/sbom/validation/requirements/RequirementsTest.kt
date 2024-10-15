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
package io.github.csaf.sbom.validation.requirements

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Tracking
import io.github.csaf.sbom.validation.ValidationContext
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationNotApplicable
import io.github.csaf.sbom.validation.ValidationSuccessful
import io.ktor.client.HttpClient
import io.ktor.client.call.HttpClientCall
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.client.statement.HttpResponse
import io.ktor.client.utils.EmptyContent
import io.ktor.http.Headers
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.headers
import io.ktor.util.Attributes
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.*
import java.math.BigDecimal
import java.net.URI
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.Job

fun goodCsaf(label: Csaf.Label = Csaf.Label.WHITE): Csaf =
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
                        aliases = setOf("alias"),
                        generator =
                            Csaf.Generator(
                                engine = Csaf.Engine(name = "csaf-exporter", version = "1.0")
                            ),
                        current_release_date =
                            OffsetDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC),
                        id = "test-title",
                        initial_release_date =
                            OffsetDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC),
                        revision_history =
                            listOf(
                                Csaf.RevisionHistory(
                                    date = OffsetDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC),
                                    number = "1.0.0-alpha1",
                                    summary = "Initial and final release",
                                    legacy_version = "1.0"
                                )
                            ),
                        status = Csaf.Status.final,
                        version = "1.0.0-alpha1",
                    ),
                distribution =
                    Csaf.Distribution(
                        tlp = Csaf.Tlp(label = label),
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
                                    sbom_urls = listOf(URI("https://example.com/sboms/my-product")),
                                    skus = listOf("123"),
                                    model_numbers = setOf("123"),
                                    serial_numbers = setOf("123"),
                                    x_generic_uris =
                                        listOf(
                                            Csaf.XGenericUri(
                                                namespace = URI("https://example.com"),
                                                uri = URI("https://example.com/my-extension"),
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
                            product_ids = setOf("test-product-name", "test-other-product-name"),
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
                                date = OffsetDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC),
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
                                        integrityRequirement =
                                            Csaf.ConfidentialityRequirement.NOT_DEFINED,
                                        availabilityRequirement =
                                            Csaf.ConfidentialityRequirement.NOT_DEFINED,
                                        temporalScore = BigDecimal.valueOf(9.0),
                                        environmentalScore = BigDecimal.valueOf(9.0),
                                    ),
                                cvss_v3 =
                                    Csaf.CvssV3(
                                        version = "3.1",
                                        vectorString =
                                            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N/E:P/RL:O/RC:C/" +
                                                "CR:M/IR:M/MAV:N/MAC:L/MPR:L/MUI:N/MS:C/MC:L/MI:L/MA:N",
                                        attackVector = Csaf.AttackVector.NETWORK,
                                        attackComplexity = Csaf.AttackComplexity.LOW,
                                        privilegesRequired = Csaf.PrivilegesRequired.LOW,
                                        userInteraction = Csaf.UserInteraction.NONE,
                                        scope = Csaf.Scope.CHANGED,
                                        confidentialityImpact = Csaf.ConfidentialityImpact1.LOW,
                                        integrityImpact = Csaf.ConfidentialityImpact1.LOW,
                                        availabilityImpact = Csaf.ConfidentialityImpact1.NONE,
                                        baseScore = BigDecimal.valueOf(6.4),
                                        baseSeverity = Csaf.BaseSeverity.MEDIUM,
                                        exploitCodeMaturity =
                                            Csaf.ExploitCodeMaturity.PROOF_OF_CONCEPT,
                                        remediationLevel = Csaf.RemediationLevel1.OFFICIAL_FIX,
                                        reportConfidence = Csaf.ReportConfidence1.CONFIRMED,
                                        temporalScore = BigDecimal.valueOf(5.8),
                                        temporalSeverity = Csaf.BaseSeverity.MEDIUM,
                                        confidentialityRequirement =
                                            Csaf.ConfidentialityRequirement1.MEDIUM,
                                        integrityRequirement =
                                            Csaf.ConfidentialityRequirement1.MEDIUM,
                                        availabilityRequirement =
                                            Csaf.ConfidentialityRequirement1.NOT_DEFINED,
                                        modifiedAttackVector = Csaf.ModifiedAttackVector.NETWORK,
                                        modifiedAttackComplexity =
                                            Csaf.ModifiedAttackComplexity.LOW,
                                        modifiedPrivilegesRequired =
                                            Csaf.ModifiedPrivilegesRequired.LOW,
                                        modifiedUserInteraction = Csaf.ModifiedUserInteraction.NONE,
                                        modifiedScope = Csaf.ModifiedScope.CHANGED,
                                        modifiedConfidentialityImpact =
                                            Csaf.ModifiedConfidentialityImpact.LOW,
                                        modifiedIntegrityImpact =
                                            Csaf.ModifiedConfidentialityImpact.LOW,
                                        modifiedAvailabilityImpact =
                                            Csaf.ModifiedConfidentialityImpact.NONE,
                                        environmentalScore = BigDecimal.valueOf(5.8),
                                        environmentalSeverity = Csaf.BaseSeverity.MEDIUM
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
                                product_ids = setOf("test-product-name", "test-other-product-name"),
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

class RequirementsTest {
    @Test
    fun testValidCSAFDocument() {
        val (rule, ctx) = testRule(Requirement1ValidCSAFDocument)

        // Empty validatable -> fail
        assertIs<ValidationFailed>(rule.check(ctx.also { it.json = null }))

        // Good validate --> success
        assertIs<ValidationSuccessful>(rule.check(ctx.also { it.json = goodCsaf() }))
    }

    @Test
    fun testValidFilename() {
        val (rule, ctx) = testRule(Requirement2ValidFilename)

        // JSON not a CSAF -> not applicable
        ctx.json = null
        assertEquals(ValidationNotApplicable, (rule.check(ctx)))

        // Invalid filename
        assertIs<ValidationFailed>(
            rule.check(
                ctx.also {
                    it.json = goodCsaf()
                    it.httpResponse = mockResponse(mockRequest(Url("/test")), HttpStatusCode.OK)
                }
            )
        )

        // Valid filename
        assertIs<ValidationSuccessful>(
            rule.check(
                ctx.also {
                    it.json = goodCsaf()
                    it.httpResponse =
                        mockResponse(mockRequest(Url("/test-title.json")), HttpStatusCode.OK)
                }
            )
        )
    }

    @Test
    fun testUsageOfTls() {
        val (rule, ctx) = testRule(Requirement3UsageOfTls)

        // No TLS -> fail
        assertIs<ValidationFailed>(
            rule.check(
                ctx.also {
                    @Suppress("HttpUrlsUsage")
                    it.httpResponse =
                        mockResponse(mockRequest(Url("http://example.com")), HttpStatusCode.OK)
                }
            )
        )

        // TLS -> success
        assertIs<ValidationSuccessful>(
            rule.check(
                ctx.also {
                    it.httpResponse =
                        mockResponse(mockRequest(Url("https://example.com")), HttpStatusCode.OK)
                }
            )
        )
    }

    @Test
    fun testTlpWhiteAccessible() {
        val (rule, ctx) = testRule(Requirement4TlpWhiteAccessible)

        // Validatable is something else -> not applicable
        assertEquals(ValidationNotApplicable, rule.check(ctx.also { it.json = null }))

        // Document is not TlpWhite -> not applicable
        assertEquals(
            ValidationNotApplicable,
            rule.check(ctx.also { it.json = goodCsaf(Csaf.Label.RED) })
        )

        // URL was retrieved with authorization headers -> fail
        assertIs<ValidationFailed>(
            rule.check(
                ctx.also {
                    it.json = goodCsaf()
                    it.httpResponse =
                        mockResponse(
                            mockRequest(
                                Url("https://example.com"),
                                headers = headers { set("Authorization", "Bearer: 1234") }
                            ),
                            HttpStatusCode.OK
                        )
                }
            )
        )

        // URL was not retrieved because of unauthorized -> fail
        assertIs<ValidationFailed>(
            rule.check(
                ctx.also {
                    it.httpResponse =
                        mockResponse(
                            mockRequest(Url("https://example.com")),
                            HttpStatusCode.Unauthorized,
                        )
                }
            )
        )

        // URL was successfully retrieved without any authorization headers -> success
        assertIs<ValidationSuccessful>(
            rule.check(
                ctx.also {
                    it.httpResponse =
                        mockResponse(
                            mockRequest(Url("https://example.com")),
                            HttpStatusCode.OK,
                        )
                }
            )
        )
    }

    @Test
    fun testRequirement8() {
        val (rule, ctx) = testRule(Requirement8SecurityTxt)

        // Data source is not security.txt -> fail
        assertIs<ValidationFailed>(
            rule.check(ctx.also { it.dataSource = ValidationContext.DataSource.WELL_KNOWN })
        )
    }

    @Test
    fun testRequirement9() {
        val (rule, ctx) = testRule(Requirement9WellKnownURL)

        // Data source is not well_known -> fail
        assertIs<ValidationFailed>(
            rule.check(ctx.also { it.dataSource = ValidationContext.DataSource.DNS })
        )
    }

    @Test
    fun testRequirement10() {
        val (rule, ctx) = testRule(Requirement10DNSPath)

        // Data source is not DNS -> fail
        assertIs<ValidationFailed>(
            rule.check(ctx.also { it.dataSource = ValidationContext.DataSource.SECURITY_TXT })
        )
    }
}

fun <T> testRule(rule: T): Pair<T, ValidationContext> {
    return Pair(rule, ValidationContext())
}

@OptIn(InternalAPI::class)
fun mockResponse(
    requestData: HttpRequestData,
    statusCode: HttpStatusCode,
    header: Headers = Headers.Empty,
): HttpResponse {
    val responseData =
        HttpResponseData(
            statusCode,
            GMTDate(),
            header,
            HttpProtocolVersion(name = "HTTP", major = 2, minor = 0),
            "",
            EmptyCoroutineContext
        )

    val call = HttpClientCall(HttpClient(), requestData, responseData)
    return call.response
}

@OptIn(InternalAPI::class)
fun mockRequest(
    url: Url,
    method: HttpMethod = HttpMethod.Get,
    headers: Headers = Headers.Empty
): HttpRequestData {
    return HttpRequestData(url, method, headers, EmptyContent, Job(), Attributes())
}
