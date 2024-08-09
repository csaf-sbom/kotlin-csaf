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

import java.net.URI
import java.time.OffsetDateTime

/** Representation of metadata information of a CSAF provider as a JSON document. */
data class Provider_json(
    /** Contains the URL for this document. */
    val canonical_url: URI,
    /** Contains a list of used distribution mechanisms. */
    val distributions: Set<Distribution>? = null,
    /** Holds the date and time when the document was last updated. */
    val last_updated: OffsetDateTime,
    /** Decides whether this file should be linked in the list of a CSAF aggregator. */
    val list_on_CSAF_aggregators: Boolean = true,
    /**
     * Gives the version of the CSAF provider metadata specification which the document was
     * generated for.
     */
    val metadata_version: String,
    /** Decides whether the CSAF documents can be mirrored and provided by a CSAF aggregator. */
    val mirror_on_CSAF_aggregators: Boolean = true,
    /** Contains a list of OpenPGP keys used to sign CSAF documents. */
    val public_openpgp_keys: List<Public_openpgp_key>? = null,
    /** Provides information about the publisher of the CSAF documents in this repository. */
    val publisher: Publisher,
    /** Contains the role of the issuing party according to section 7 in the CSAF standard. */
    val role: Role = Role.csaf_provider
) {

    init {
        if (distributions != null)
            require(distributions.isNotEmpty()) {
                "distributions length < minimum 1 - ${distributions.size}"
            }
        require(metadata_version in cg_array0) {
            "metadata_version not in enumerated values - $metadata_version"
        }
    }

    /** Contains the information of a used distribution mechanism. */
    data class Distribution(
        /** Contains the base url for the directory distribution. */
        val directory_url: URI? = null,
        /** Contains all information for ROLIE distribution. */
        val rolie: Rolie? = null
    )

    /** Contains all information for ROLIE distribution. */
    data class Rolie(
        /** Contains a list of URLs which contain ROLIE category documents. */
        val categories: Set<URI>? = null,
        /** Contains a list of information about ROLIE feeds. */
        val feeds: Set<Feed>,
        /** Contains a list of URLs which contain ROLIE service documents. */
        val services: Set<URI>? = null
    ) {

        init {
            if (categories != null)
                require(categories.isNotEmpty()) {
                    "categories length < minimum 1 - ${categories.size}"
                }
            require(feeds.isNotEmpty()) { "feeds length < minimum 1 - ${feeds.size}" }
            if (services != null)
                require(services.isNotEmpty()) { "services length < minimum 1 - ${services.size}" }
        }
    }

    /** Contains information about the ROLIE feed. */
    data class Feed(
        /** Contains a summary of the feed. */
        val summary: String? = null,
        /** Provides the TLP label for the feed. */
        val tlp_label: Tlp_label,
        /** Contains the URL of the feed. */
        val url: URI
    )

    /** Provides the TLP label for the feed. */
    enum class Tlp_label {
        UNLABELED,
        WHITE,
        GREEN,
        AMBER,
        RED
    }

    /** Contains all information about an OpenPGP key used to sign CSAF documents. */
    data class Public_openpgp_key(
        /** Contains the fingerprint of the OpenPGP key. */
        val fingerprint: String? = null,
        /** Contains the URL where the key can be retrieved. */
        val url: URI
    ) {

        init {
            if (fingerprint != null) {
                require(fingerprint.length >= 40) {
                    "fingerprint length < minimum 40 - ${fingerprint.length}"
                }
                require(cg_regex1.containsMatchIn(fingerprint)) {
                    "fingerprint does not match pattern $cg_regex1 - $fingerprint"
                }
            }
        }
    }

    /** Provides information about the publisher of the CSAF documents in this repository. */
    data class Publisher(
        /** Provides information about the category of publisher releasing the document. */
        val category: Category,
        /**
         * Information on how to contact the publisher, possibly including details such as web
         * sites, email addresses, phone numbers, and postal mail addresses.
         */
        val contact_details: String? = null,
        /**
         * Provides information about the authority of the issuing party to release the document, in
         * particular, the party's constituency and responsibilities or other obligations.
         */
        val issuing_authority: String? = null,
        /** Contains the name of the issuing party. */
        val name: String,
        /**
         * Contains a URL which is under control of the issuing party and can be used as a globally
         * unique identifier for that issuing party.
         */
        val namespace: URI
    ) {

        init {
            if (contact_details != null)
                require(contact_details.isNotEmpty()) {
                    "contact_details length < minimum 1 - ${contact_details.length}"
                }
            if (issuing_authority != null)
                require(issuing_authority.isNotEmpty()) {
                    "issuing_authority length < minimum 1 - ${issuing_authority.length}"
                }
            require(name.isNotEmpty()) { "name length < minimum 1 - ${name.length}" }
        }
    }

    /** Provides information about the category of publisher releasing the document. */
    enum class Category {
        coordinator,
        discoverer,
        other,
        translator,
        user,
        vendor
    }

    /** Contains the role of the issuing party according to section 7 in the CSAF standard. */
    enum class Role {
        csaf_publisher,
        csaf_provider,
        csaf_trusted_provider
    }

    companion object {
        private val cg_array0 = setOf("2.0")
        private val cg_regex1 = Regex("^[0-9a-fA-F]{40,}\$")
    }
}
