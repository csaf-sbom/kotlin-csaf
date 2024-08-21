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

import io.github.csaf.sbom.generated.Provider
import java.net.URI
import java.time.OffsetDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class ProviderTest {
    @Test
    fun testGoodProvider() {
        var provider =
            Provider(
                canonical_url = URI("example.com/publisher.json"),
                last_updated = OffsetDateTime.now(),
                metadata_version = "2.0",
                publisher =
                    Provider.Publisher(
                        category = Provider.Category.vendor,
                        name = "Test Aggregator",
                        namespace = URI("example.com"),
                    ),
            )
        assertNotNull(provider)
    }

    @Test
    fun testFailMetadataVersion() {
        var exception =
            assertFailsWith<IllegalArgumentException> {
                Provider(
                    canonical_url = URI("example.com/publisher.json"),
                    last_updated = OffsetDateTime.now(),
                    metadata_version = "abc",
                    distributions =
                        setOf(
                            Provider.Distribution(
                                directory_url = URI("example.com/csaf"),
                                rolie =
                                    Provider.Rolie(
                                        feeds =
                                            setOf(
                                                Provider.Feed(
                                                    tlp_label = Provider.TlpLabel.WHITE,
                                                    url =
                                                        URI(
                                                            "example.com/csaf/feeds/white/feed.json"
                                                        ),
                                                    summary = "White Advisories"
                                                )
                                            )
                                    )
                            )
                        ),
                    publisher =
                        Provider.Publisher(
                            category = Provider.Category.vendor,
                            name = "Test Publisher",
                            namespace = URI("example.com"),
                        ),
                    public_openpgp_keys =
                        listOf(
                            Provider.PublicOpenpgpKey(
                                url = URI("example.com/key_public.asc"),
                                fingerprint = "ABC1234ABC1234ABC1234ABC1234ABC1234ABC12",
                            )
                        )
                )
            }
        assertEquals("metadata_version not in enumerated values - abc", exception.message)
    }
}
