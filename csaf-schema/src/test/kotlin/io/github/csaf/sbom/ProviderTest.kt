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

class ProviderTest {
    @Test
    fun testProvider() {
        PojoTestHelper.testAll { valGen ->
            Provider(
                canonical_url = URI("example.com/publisher.json"),
                last_updated = OffsetDateTime.now(),
                metadata_version =
                    valGen(Provider::metadata_version, "2.0", invalidList = listOf("1.0")),
                distributions =
                    valGen(
                        Provider::distributions,
                        setOf(
                            Provider.Distribution(
                                directory_url = URI("example.com/csaf"),
                                rolie =
                                    Provider.Rolie(
                                        categories =
                                            valGen(
                                                Provider.Rolie::categories,
                                                setOf(URI("example.com/csaf/feeds/categories.json"))
                                            ),
                                        services =
                                            valGen(
                                                Provider.Rolie::services,
                                                setOf(URI("example.com/csaf/feeds/services.json"))
                                            ),
                                        feeds =
                                            valGen(
                                                Provider.Rolie::feeds,
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
                            )
                        )
                    ),
                publisher =
                    valGen(
                        Provider::publisher,
                        Provider.Publisher(
                            category = Provider.Category.vendor,
                            name = valGen(Provider.Publisher::name, "Test Aggregator"),
                            namespace = URI("example.com"),
                            contact_details =
                                valGen(Provider.Publisher::contact_details, "security@example.com"),
                            issuing_authority =
                                valGen(Provider.Publisher::issuing_authority, "Very authoritative")
                        )
                    ),
                public_openpgp_keys =
                    listOf(
                        Provider.PublicOpenpgpKey(
                            url = URI("example.com/key_public.asc"),
                            fingerprint =
                                valGen(
                                    Provider.PublicOpenpgpKey::fingerprint,
                                    "ABCDEABCDE1234567890ABCDEABCDE1234567890",
                                    invalidList =
                                        listOf(
                                            "12345678901234567890",
                                            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                        )
                                ),
                        )
                    )
            )
        }
    }

    @Test
    fun testFailMetadataVersion() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                Provider(
                    canonical_url = URI("example.com/publisher.json"),
                    last_updated = OffsetDateTime.now(),
                    metadata_version = "abc",
                    publisher =
                        Provider.Publisher(
                            category = Provider.Category.vendor,
                            name = "Test Publisher",
                            namespace = URI("example.com"),
                        )
                )
            }
        assertEquals("metadata_version not in enumerated values - abc", exception.message)
    }
}