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
package com.github.csaf.generated

import com.github.csaf.generated.Aggregator_json.Metadata_t
import com.github.csaf.generated.Aggregator_json.Publisher
import java.net.URI
import java.time.OffsetDateTime
import kotlin.test.Test
import kotlin.test.assertNotNull

class AggregatorTest {
    @Test
    fun testObject() {
        var doc =
            Aggregator_json(
                aggregator =
                    Aggregator_json.Aggregator(
                        category = Aggregator_json.Category.aggregator,
                        name = "Test Aggregator",
                        namespace = URI("example.com"),
                    ),
                aggregator_version = "2.0",
                canonical_url = URI("example.com/aggregator.json"),
                csaf_providers =
                    setOf(
                        Aggregator_json.Csaf_provider(
                            metadata =
                                Metadata_t(
                                    last_updated = OffsetDateTime.now(),
                                    publisher =
                                        Publisher(
                                            category = Aggregator_json.Category1.vendor,
                                            name = "Test Aggregator",
                                            namespace = URI("example.com"),
                                        ),
                                    url = URI("example.com/publisher.json")
                                ),
                        ),
                    ),
                last_updated = OffsetDateTime.now(),
            )
        assertNotNull(doc)
    }
}
