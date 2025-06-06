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
package io.csaf.schema

import io.csaf.schema.generated.Aggregator
import io.csaf.schema.generated.Aggregator.*
import java.time.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class AggregatorTest {
    @Test
    fun testAggregator() {
        val example =
            PojoTestHelper.testAll { valGen ->
                Aggregator(
                    aggregator =
                        Aggregator(
                            category = Category.aggregator,
                            name = valGen(Aggregator.Aggregator::name, "Test Aggregator"),
                            namespace = JsonUri("example.com"),
                            contact_details =
                                valGen(
                                    Aggregator.Aggregator::contact_details,
                                    "security@example.com",
                                ),
                            issuing_authority =
                                valGen(
                                    Aggregator.Aggregator::issuing_authority,
                                    "Very authoritative",
                                ),
                        ),
                    aggregator_version =
                        valGen(Aggregator::aggregator_version, "2.0", invalidList = listOf("1.0")),
                    canonical_url = JsonUri("example.com/aggregator.json"),
                    csaf_publishers =
                        valGen(
                            Aggregator::csaf_publishers,
                            setOf(
                                CsafPublisher(
                                    metadata =
                                        Metadata(
                                            last_updated = epoch(),
                                            publisher =
                                                Publisher(
                                                    category = Category1.vendor,
                                                    name = "Test Aggregator",
                                                    namespace = JsonUri("example.com"),
                                                ),
                                            url = JsonUri("example.com/publisher.json"),
                                        ),
                                    update_interval = valGen(CsafPublisher::update_interval, "5m"),
                                    mirrors =
                                        valGen(
                                            CsafPublisher::mirrors,
                                            setOf(
                                                JsonUri("https://mirror.example.com/publisher.json")
                                            ),
                                        ),
                                )
                            ),
                        ),
                    csaf_providers =
                        valGen(
                            Aggregator::csaf_providers,
                            setOf(
                                CsafProvider(
                                    metadata =
                                        Metadata(
                                            last_updated = epoch(),
                                            publisher =
                                                Publisher(
                                                    category = Category1.vendor,
                                                    name =
                                                        valGen(Publisher::name, "Test Publisher"),
                                                    namespace = JsonUri("example.com"),
                                                    contact_details =
                                                        valGen(
                                                            Publisher::contact_details,
                                                            "security@example.com",
                                                        ),
                                                    issuing_authority =
                                                        valGen(
                                                            Publisher::issuing_authority,
                                                            "Very authoritative",
                                                        ),
                                                ),
                                            url = JsonUri("https://example.com/provider.json"),
                                        ),
                                    mirrors =
                                        valGen(
                                            CsafProvider::mirrors,
                                            setOf(
                                                JsonUri("https://mirror.example.com/provider.json")
                                            ),
                                        ),
                                )
                            ),
                        ),
                    last_updated = epoch(),
                )
            }
        // One may use this code snippet to update the reference JSON in case of structure changes.
        //        Files.writeString(
        //            Path.of("src/test/resources/aggregator.json"),
        //            assertNotNull(Json.encodeToString(example))
        //        )
        assertEquals(
            PojoTestHelper.readFileFromResources("aggregator.json"),
            Json.encodeToString(example),
        )
    }
}
