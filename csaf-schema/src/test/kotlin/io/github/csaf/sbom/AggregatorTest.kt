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

class AggregatorTest {
    @Test
    fun testGoodAggregator() {
        val doc =
            Aggregator(
                aggregator =
                    Aggregator(
                        category = Category.aggregator,
                        name = "Test Aggregator",
                        namespace = URI("example.com"),
                        contact_details = "security@example.com",
                        issuing_authority = "Very authoritative",
                    ),
                aggregator_version = "2.0",
                canonical_url = URI("example.com/aggregator.json"),
                csaf_publishers =
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
                            update_interval = "5m",
                            mirrors = setOf(URI("https://mirror.example.com/provider.json"))
                        ),
                    ),
                csaf_providers =
                    setOf(
                        CsafProvider(
                            metadata =
                                Metadata(
                                    last_updated = OffsetDateTime.now(),
                                    publisher =
                                        Publisher(
                                            category = Category1.vendor,
                                            name = "Test Aggregator",
                                            namespace = URI("example.com"),
                                            contact_details = "security@example.com",
                                            issuing_authority = "Very authoritative",
                                        ),
                                    url = URI("https://example.com/provider.json")
                                ),
                            mirrors = setOf(URI("https://mirror.example.com/provider.json"))
                        ),
                    ),
                last_updated = OffsetDateTime.now(),
            )
        assertNotNull(doc)
    }
}
