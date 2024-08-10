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

/** Representation of information where to find CSAF providers as a JSON document. */
data class Aggregator_json(
    /** Provides information about the aggregator. */
    val aggregator: Aggregator,
    /**
     * Gives the version of the CSAF aggregator specification which the document was generated for.
     */
    val aggregator_version: String,
    /** Contains the URL for this document. */
    val canonical_url: URI,
    /** Contains a list with information from CSAF providers. */
    val csaf_providers: Set<Csaf_provider>,
    /** Contains a list with information from CSAF publishers. */
    val csaf_publishers: Set<Csaf_publisher>? = null,
    /** Holds the date and time when the document was last updated. */
    val last_updated: OffsetDateTime
) {

    init {
        require(aggregator_version in cg_array0) {
            "aggregator_version not in enumerated values - $aggregator_version"
        }
        require(csaf_providers.isNotEmpty()) {
            "csaf_providers length < minimum 1 - ${csaf_providers.size}"
        }
        if (csaf_publishers != null)
            require(csaf_publishers.isNotEmpty()) {
                "csaf_publishers length < minimum 1 - ${csaf_publishers.size}"
            }
    }

    /** Provides information about the aggregator. */
    data class Aggregator(
        /** Provides information about the category of aggregator. */
        val category: Category,
        /**
         * Information on how to contact the aggregator, possibly including details such as web
         * sites, email addresses, phone numbers, and postal mail addresses.
         */
        val contact_details: String? = null,
        /**
         * Provides information about the authority of the aggregator to release the list, in
         * particular, the party's constituency and responsibilities or other obligations.
         */
        val issuing_authority: String? = null,
        /** Contains the name of the aggregator. */
        val name: String,
        /**
         * Contains a URL which is under control of the aggregator and can be used as a globally
         * unique identifier for that aggregator.
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

    /** Provides information about the category of aggregator. */
    enum class Category {
        aggregator,
        lister
    }

    /** Contains information from a CSAF provider. */
    data class Csaf_provider(
        /** Contains the metadata of a single CSAF provider. */
        val metadata: Metadata_t,
        /** Contains a list of URLs or mirrors for this CSAF provider. */
        val mirrors: Set<URI>? = null
    ) {

        init {
            if (mirrors != null)
                require(mirrors.isNotEmpty()) { "mirrors length < minimum 1 - ${mirrors.size}" }
        }
    }

    /** Contains the metadata of a single CSAF provider. */
    data class Metadata_t(
        /** Holds the date and time when this entry was last updated. */
        val last_updated: OffsetDateTime,
        /** Provides information about the issuing party for this entry. */
        val publisher: Publisher,
        /** Contains the role of the issuing party according to section 7 in the CSAF standard. */
        val role: Role = Role.csaf_provider,
        /** Contains the URL of the provider-metadata.json for that entry. */
        val url: URI
    )

    /** Provides information about the issuing party for this entry. */
    data class Publisher(
        /** Provides information about the category of publisher releasing the document. */
        val category: Category1,
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
    enum class Category1 {
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

    /** Contains information from a CSAF publisher. */
    data class Csaf_publisher(
        /**
         * Contains the metadata of a single CSAF publisher extracted from one of its CSAF
         * documents.
         */
        val metadata: Metadata_t,
        /** Contains a list of URLs or mirrors for this CSAF publisher. */
        val mirrors: Set<URI>? = null,
        /**
         * Contains information about how often the CSAF publisher is checked for new CSAF
         * documents.
         */
        val update_interval: String
    ) {

        init {
            if (mirrors != null)
                require(mirrors.isNotEmpty()) { "mirrors length < minimum 1 - ${mirrors.size}" }
            require(update_interval.isNotEmpty()) {
                "update_interval length < minimum 1 - ${update_interval.length}"
            }
        }
    }

    companion object {
        private val cg_array0 = setOf("2.0")
    }
}
