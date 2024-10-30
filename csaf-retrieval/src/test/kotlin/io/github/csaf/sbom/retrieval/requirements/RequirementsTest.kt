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
package io.github.csaf.sbom.retrieval.requirements

import io.github.csaf.sbom.retrieval.RetrievalContext
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationNotApplicable
import io.github.csaf.sbom.validation.ValidationSuccessful
import io.github.csaf.sbom.validation.goodCsaf
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
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.Job

class RequirementsTest {
    @Test
    fun testValidCSAFDocument() {
        val (rule, ctx) = testRule(Requirement1ValidCSAFDocument)

        // Empty validatable -> fail
        assertIs<ValidationFailed>(rule.check(ctx.also { ctx.json = null }))

        // Good validate --> success
        assertEquals(ValidationSuccessful, rule.check(ctx.also { ctx.json = goodCsaf() }))
    }

    @Test
    fun testValidFilename() {
        val (rule, ctx) = testRule(Requirement2ValidFilename)

        // JSON not a CSAF -> not applicable
        ctx.json = null
        assertEquals(ValidationNotApplicable, rule.check(ctx))

        // Invalid filename
        assertIs<ValidationFailed>(
            rule.check(
                ctx.also {
                    ctx.json = goodCsaf()
                    ctx.httpResponse = mockResponse(mockRequest(Url("/test")), HttpStatusCode.OK)
                }
            )
        )

        // Valid filename
        assertIs<ValidationSuccessful>(
            rule.check(
                ctx.also {
                    ctx.json = goodCsaf()
                    ctx.httpResponse =
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
                    ctx.httpResponse =
                        mockResponse(mockRequest(Url("http://example.com")), HttpStatusCode.OK)
                }
            )
        )

        // TLS -> success
        assertIs<ValidationSuccessful>(
            rule.check(
                ctx.also {
                    ctx.httpResponse =
                        mockResponse(mockRequest(Url("https://example.com")), HttpStatusCode.OK)
                }
            )
        )
    }

    @Test
    fun testTlpWhiteAccessible() {
        val (rule, ctx) = testRule(Requirement4TlpWhiteAccessible)

        // Validatable is something else -> not applicable
        assertEquals(ValidationNotApplicable, rule.check(ctx.also { ctx.json = null }))

        // Document is not TlpWhite -> not applicable
        assertEquals(
            ValidationNotApplicable,
            rule.check(ctx.also { ctx.json = goodCsaf(Csaf.Label.RED) })
        )

        // URL was retrieved with authorization headers -> fail
        assertIs<ValidationFailed>(
            rule.check(
                ctx.also {
                    ctx.json = goodCsaf()
                    ctx.httpResponse =
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
                    ctx.httpResponse =
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
                    ctx.httpResponse =
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
            rule.check(ctx.also { ctx.dataSource = RetrievalContext.DataSource.WELL_KNOWN })
        )
    }

    @Test
    fun testRequirement9() {
        val (rule, ctx) = testRule(Requirement9WellKnownURL)

        // Data source is not well_known -> fail
        assertIs<ValidationFailed>(
            rule.check(ctx.also { ctx.dataSource = RetrievalContext.DataSource.DNS })
        )
    }

    @Test
    fun testRequirement10() {
        val (rule, ctx) = testRule(Requirement10DNSPath)

        // Data source is not DNS -> fail
        assertIs<ValidationFailed>(
            rule.check(ctx.also { ctx.dataSource = RetrievalContext.DataSource.SECURITY_TXT })
        )
    }
}

fun <T> testRule(rule: T): Pair<T, RetrievalContext> {
    return Pair(rule, RetrievalContext())
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
