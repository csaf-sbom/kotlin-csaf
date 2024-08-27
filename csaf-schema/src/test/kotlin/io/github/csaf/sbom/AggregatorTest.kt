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

import io.github.csaf.sbom.generated.Aggregator
import io.github.csaf.sbom.generated.Aggregator.*
import java.net.URI
import java.time.OffsetDateTime
import kotlin.test.Test
import kotlin.test.assertNotNull
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

@Suppress("UNCHECKED_CAST")
class AggregatorTest {
    private fun buildAggregator(map: Map<String, Any?>) =
        Aggregator(
            aggregator =
                Aggregator(
                    category = Category.aggregator,
                    name = map["agName"] as String,
                    namespace = URI("example.com"),
                    contact_details = map["agContactDetails"] as String?,
                    issuing_authority = map["agIssuingAuthority"] as String?,
                ),
            aggregator_version = map["agVersion"] as String,
            canonical_url = URI("example.com/aggregator.json"),
            csaf_publishers =
                if (map.containsKey("publishers")) {
                    map["publishers"] as Set<CsafPublisher>?
                } else {
                    setOf(
                        CsafPublisher(
                            metadata =
                                Metadata(
                                    last_updated = OffsetDateTime.now(),
                                    publisher =
                                        Publisher(
                                            category = Category1.vendor,
                                            name = "Test Aggregator",
                                            namespace = URI("example.com"),
                                        ),
                                    url = URI("example.com/publisher.json")
                                ),
                            update_interval = map["updateInterval"] as String,
                            mirrors = map["pubMirrors"] as Set<URI>?
                        ),
                    )
                },
            csaf_providers =
                if (map.containsKey("providers")) {
                    map["providers"] as Set<CsafProvider>
                } else {
                    setOf(
                        CsafProvider(
                            metadata =
                                Metadata(
                                    last_updated = OffsetDateTime.now(),
                                    publisher =
                                        Publisher(
                                            category = Category1.vendor,
                                            name = map["pubName"] as String,
                                            namespace = URI("example.com"),
                                            contact_details = map["pubContactDetails"] as String?,
                                            issuing_authority =
                                                map["pubIssuingAuthority"] as String?
                                        ),
                                    url = URI("https://example.com/provider.json")
                                ),
                            mirrors = map["provMirrors"] as Set<URI>?
                        ),
                    )
                },
            last_updated = OffsetDateTime.now(),
        )

    @Test
    fun testGoodAggregator() {
        assertDoesNotThrow { buildAggregator(DEFAULTS) }
    }

    @Test
    fun testAlternativeValues() {
        VALID_VALUES.forEach { pair ->
            assertDoesNotThrow { assertNotNull(buildAggregator(DEFAULTS + mapOf(pair))) }
        }
    }

    @Test
    fun testIllegalValues() {
        ILLEGAL_VALUES.forEach { pair ->
            assertThrows<IllegalArgumentException> { buildAggregator(DEFAULTS + mapOf(pair)) }
        }
    }

    companion object {
        val DEFAULTS: Map<String, Any?> =
            mapOf(
                "agName" to "Test Aggregator",
                "agContactDetails" to "security@example.com",
                "agIssuingAuthority" to "Very authoritative",
                "agVersion" to "2.0",
                "provMirrors" to setOf(URI("https://mirror.example.com/provider.json")),
                "pubMirrors" to setOf(URI("https://mirror.example.com/provider.json")),
                "pubName" to "Test Aggregator",
                "pubContactDetails" to "security@example.com",
                "pubIssuingAuthority" to "Very authoritative",
                "updateInterval" to "5m",
            )
        val VALID_VALUES: List<Pair<String, Any?>> =
            listOf(
                "agContactDetails" to null,
                "agIssuingAuthority" to null,
                "publishers" to null,
                "provMirrors" to null,
                "pubMirrors" to null,
                "pubContactDetails" to null,
                "pubIssuingAuthority" to null,
            )
        val ILLEGAL_VALUES: List<Pair<String, Any?>> =
            listOf(
                "agName" to "",
                "agContactDetails" to "",
                "agIssuingAuthority" to "",
                "agVersion" to "1.0",
                "publishers" to emptySet<CsafPublisher>(),
                "providers" to emptySet<CsafProvider>(),
                "provMirrors" to emptySet<URI>(),
                "pubMirrors" to emptySet<URI>(),
                "pubName" to "",
                "pubContactDetails" to "",
                "pubIssuingAuthority" to "",
                "updateInterval" to "",
            )
    }
}
