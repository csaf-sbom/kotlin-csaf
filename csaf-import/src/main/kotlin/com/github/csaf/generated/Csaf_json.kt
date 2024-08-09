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

import java.math.BigDecimal
import java.net.URI
import java.time.OffsetDateTime

/** Representation of security advisory information as a JSON document. */
data class Csaf_json(
    /**
     * Captures the meta-data about this document describing a particular set of security
     * advisories.
     */
    val document: Document,
    /**
     * Is a container for all fully qualified product names that can be referenced elsewhere in the
     * document.
     */
    val product_tree: Product_tree? = null,
    /** Represents a list of all relevant vulnerability information items. */
    val vulnerabilities: List<Vulnerabilitie>? = null
) {

    init {
        if (vulnerabilities != null)
            require(vulnerabilities.isNotEmpty()) {
                "vulnerabilities length < minimum 1 - ${vulnerabilities.size}"
            }
    }

    /**
     * Captures the meta-data about this document describing a particular set of security
     * advisories.
     */
    data class Document(
        /** Contains a list of acknowledgment elements associated with the whole document. */
        val acknowledgments: List<Acknowledgments_t>? = null,
        /**
         * Is a vehicle that is provided by the document producer to convey the urgency and
         * criticality with which the one or more vulnerabilities reported should be addressed. It
         * is a document-level metric and applied to the document as a whole — not any specific
         * vulnerability. The range of values in this field is defined according to the document
         * producer's policies and procedures.
         */
        val aggregate_severity: Aggregate_severity? = null,
        /**
         * Defines a short canonical name, chosen by the document producer, which will inform the
         * end user as to the category of document.
         */
        val category: String,
        /** Gives the version of the CSAF specification which the document was generated for. */
        val csaf_version: String,
        /** Describe any constraints on how this document might be shared. */
        val distribution: Distribution? = null,
        /**
         * Identifies the language used by this document, corresponding to IETF BCP 47 / RFC 5646.
         */
        val lang: String? = null,
        /** Holds notes associated with the whole document. */
        val notes: List<Notes_t>? = null,
        /** Provides information about the publisher of the document. */
        val publisher: Publisher,
        /** Holds a list of references associated with the whole document. */
        val references: List<References_t>? = null,
        /**
         * If this copy of the document is a translation then the value of this property describes
         * from which language this document was translated.
         */
        val source_lang: String? = null,
        /**
         * This SHOULD be a canonical name for the document, and sufficiently unique to distinguish
         * it from similar documents.
         */
        val title: String,
        /**
         * Is a container designated to hold all management attributes necessary to track a CSAF
         * document as a whole.
         */
        val tracking: Tracking
    ) {

        init {
            if (acknowledgments != null)
                require(acknowledgments.isNotEmpty()) {
                    "acknowledgments length < minimum 1 - ${acknowledgments.size}"
                }
            require(category.isNotEmpty()) { "category length < minimum 1 - ${category.length}" }
            require(cg_regex0.containsMatchIn(category)) {
                "category does not match pattern $cg_regex0 - $category"
            }
            require(csaf_version in cg_array1) {
                "csaf_version not in enumerated values - $csaf_version"
            }
            if (lang != null)
                require(cg_regex2.containsMatchIn(lang)) {
                    "lang does not match pattern $cg_regex2 - $lang"
                }
            if (notes != null)
                require(notes.isNotEmpty()) { "notes length < minimum 1 - ${notes.size}" }
            if (references != null)
                require(references.isNotEmpty()) {
                    "references length < minimum 1 - ${references.size}"
                }
            if (source_lang != null)
                require(cg_regex2.containsMatchIn(source_lang)) {
                    "source_lang does not match pattern $cg_regex2 - $source_lang"
                }
            require(title.isNotEmpty()) { "title length < minimum 1 - ${title.length}" }
        }
    }

    /** Acknowledges contributions by describing those that contributed. */
    data class Acknowledgments_t(
        /** Contains the names of contributors being recognized. */
        val names: List<String>? = null,
        /** Contains the name of a contributing organization being recognized. */
        val organization: String? = null,
        /**
         * SHOULD represent any contextual details the document producers wish to make known about
         * the acknowledgment or acknowledged parties.
         */
        val summary: String? = null,
        /** Specifies a list of URLs or location of the reference to be acknowledged. */
        val urls: List<URI>? = null
    ) {

        init {
            if (names != null) {
                for (cg_1 in names) require(cg_1.isNotEmpty()) {
                    "names item length < minimum 1 - ${cg_1.length}"
                }
                require(names.isNotEmpty()) { "names length < minimum 1 - ${names.size}" }
            }
            if (organization != null)
                require(organization.isNotEmpty()) {
                    "organization length < minimum 1 - ${organization.length}"
                }
            if (summary != null)
                require(summary.isNotEmpty()) { "summary length < minimum 1 - ${summary.length}" }
            if (urls != null)
                require(urls.isNotEmpty()) { "urls length < minimum 1 - ${urls.size}" }
        }
    }

    /**
     * Is a vehicle that is provided by the document producer to convey the urgency and criticality
     * with which the one or more vulnerabilities reported should be addressed. It is a
     * document-level metric and applied to the document as a whole — not any specific
     * vulnerability. The range of values in this field is defined according to the document
     * producer's policies and procedures.
     */
    data class Aggregate_severity(
        /** Points to the namespace so referenced. */
        val namespace: URI? = null,
        /**
         * Provides a severity which is independent of - and in addition to - any other standard
         * metric for determining the impact or severity of a given vulnerability (such as CVSS).
         */
        val text: String
    ) {

        init {
            require(text.isNotEmpty()) { "text length < minimum 1 - ${text.length}" }
        }
    }

    /** Describe any constraints on how this document might be shared. */
    data class Distribution(
        /** Provides a textual description of additional constraints. */
        val text: String? = null,
        /** Provides details about the TLP classification of the document. */
        val tlp: Tlp? = null
    ) {

        init {
            if (text != null)
                require(text.isNotEmpty()) { "text length < minimum 1 - ${text.length}" }
        }
    }

    /** Provides details about the TLP classification of the document. */
    data class Tlp(
        /** Provides the TLP label of the document. */
        val label: Label,
        /**
         * Provides a URL where to find the textual description of the TLP version which is used in
         * this document. Default is the URL to the definition by FIRST.
         */
        val url: URI = URI("https://www.first.org/tlp/")
    )

    /** Provides the TLP label of the document. */
    enum class Label {
        AMBER,
        GREEN,
        RED,
        WHITE
    }

    /** Is a place to put all manner of text blobs related to the current context. */
    data class Notes_t(
        /** Indicates who is intended to read it. */
        val audience: String? = null,
        /** Contains the information of what kind of note this is. */
        val category: Category,
        /** Holds the content of the note. Content varies depending on type. */
        val text: String,
        /** Provides a concise description of what is contained in the text of the note. */
        val title: String? = null
    ) {

        init {
            if (audience != null)
                require(audience.isNotEmpty()) {
                    "audience length < minimum 1 - ${audience.length}"
                }
            require(text.isNotEmpty()) { "text length < minimum 1 - ${text.length}" }
            if (title != null)
                require(title.isNotEmpty()) { "title length < minimum 1 - ${title.length}" }
        }
    }

    /** Contains the information of what kind of note this is. */
    enum class Category {
        description,
        details,
        faq,
        general,
        legal_disclaimer,
        other,
        summary
    }

    /** Provides information about the publisher of the document. */
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

    /**
     * Holds any reference to conferences, papers, advisories, and other resources that are related
     * and considered related to either a surrounding part of or the entire document and to be of
     * value to the document consumer.
     */
    data class References_t(
        /**
         * Indicates whether the reference points to the same document or vulnerability in focus
         * (depending on scope) or to an external resource.
         */
        val category: Category2 = Category2.external,
        /** Indicates what this reference refers to. */
        val summary: String,
        /** Provides the URL for the reference. */
        val url: URI
    ) {

        init {
            require(summary.isNotEmpty()) { "summary length < minimum 1 - ${summary.length}" }
        }
    }

    /**
     * Indicates whether the reference points to the same document or vulnerability in focus
     * (depending on scope) or to an external resource.
     */
    enum class Category2 {
        external,
        self
    }

    /**
     * Is a container designated to hold all management attributes necessary to track a CSAF
     * document as a whole.
     */
    data class Tracking(
        /** Contains a list of alternate names for the same document. */
        val aliases: Set<String>? = null,
        /** The date when the current revision of this document was released */
        val current_release_date: OffsetDateTime,
        /**
         * Is a container to hold all elements related to the generation of the document. These
         * items will reference when the document was actually created, including the date it was
         * generated and the entity that generated it.
         */
        val generator: Generator? = null,
        /**
         * The ID is a simple label that provides for a wide range of numbering values, types, and
         * schemes. Its value SHOULD be assigned and maintained by the original document issuing
         * authority.
         */
        val id: String,
        /** The date when this document was first published. */
        val initial_release_date: OffsetDateTime,
        /**
         * Holds one revision item for each version of the CSAF document, including the initial one.
         */
        val revision_history: List<Revision_history>,
        /** Defines the draft status of the document. */
        val status: Status,
        val version: String
    ) {

        init {
            if (aliases != null) {
                for (cg_5 in aliases) require(cg_5.isNotEmpty()) {
                    "aliases item length < minimum 1 - ${cg_5.length}"
                }
                require(aliases.isNotEmpty()) { "aliases length < minimum 1 - ${aliases.size}" }
            }
            require(id.isNotEmpty()) { "id length < minimum 1 - ${id.length}" }
            require(cg_regex3.containsMatchIn(id)) { "id does not match pattern $cg_regex3 - $id" }
            require(revision_history.isNotEmpty()) {
                "revision_history length < minimum 1 - ${revision_history.size}"
            }
            require(cg_regex4.containsMatchIn(version)) {
                "version does not match pattern $cg_regex4 - $version"
            }
        }
    }

    /**
     * Is a container to hold all elements related to the generation of the document. These items
     * will reference when the document was actually created, including the date it was generated
     * and the entity that generated it.
     */
    data class Generator(
        /**
         * This SHOULD be the current date that the document was generated. Because documents are
         * often generated internally by a document producer and exist for a nonzero amount of time
         * before being released, this field MAY be different from the Initial Release Date and
         * Current Release Date.
         */
        val date: OffsetDateTime? = null,
        /** Contains information about the engine that generated the CSAF document. */
        val engine: Engine
    )

    /** Contains information about the engine that generated the CSAF document. */
    data class Engine(
        /** Represents the name of the engine that generated the CSAF document. */
        val name: String,
        /** Contains the version of the engine that generated the CSAF document. */
        val version: String? = null
    ) {

        init {
            require(name.isNotEmpty()) { "name length < minimum 1 - ${name.length}" }
            if (version != null)
                require(version.isNotEmpty()) { "version length < minimum 1 - ${version.length}" }
        }
    }

    /** Contains all the information elements required to track the evolution of a CSAF document. */
    data class Revision_history(
        /** The date of the revision entry */
        val date: OffsetDateTime,
        /** Contains the version string used in an existing document with the same content. */
        val legacy_version: String? = null,
        val number: String,
        /** Holds a single non-empty string representing a short description of the changes. */
        val summary: String
    ) {

        init {
            if (legacy_version != null)
                require(legacy_version.isNotEmpty()) {
                    "legacy_version length < minimum 1 - ${legacy_version.length}"
                }
            require(cg_regex4.containsMatchIn(number)) {
                "number does not match pattern $cg_regex4 - $number"
            }
            require(summary.isNotEmpty()) { "summary length < minimum 1 - ${summary.length}" }
        }
    }

    /** Defines the draft status of the document. */
    enum class Status {
        draft,
        final,
        interim
    }

    /**
     * Is a container for all fully qualified product names that can be referenced elsewhere in the
     * document.
     */
    data class Product_tree(
        val branches: List<Branches_t>? = null,
        /** Contains a list of full product names. */
        val full_product_names: List<Full_product_name_t>? = null,
        /** Contains a list of product groups. */
        val product_groups: List<Product_group>? = null,
        /** Contains a list of relationships. */
        val relationships: List<Relationship>? = null
    ) {

        init {
            if (branches != null)
                require(branches.isNotEmpty()) { "branches length < minimum 1 - ${branches.size}" }
            if (full_product_names != null)
                require(full_product_names.isNotEmpty()) {
                    "full_product_names length < minimum 1 - ${full_product_names.size}"
                }
            if (product_groups != null)
                require(product_groups.isNotEmpty()) {
                    "product_groups length < minimum 1 - ${product_groups.size}"
                }
            if (relationships != null)
                require(relationships.isNotEmpty()) {
                    "relationships length < minimum 1 - ${relationships.size}"
                }
        }
    }

    /** Is a part of the hierarchical structure of the product tree. */
    data class Branches_t(
        /** Describes the characteristics of the labeled branch. */
        val category: Category3,
        /** Contains the canonical descriptor or 'friendly name' of the branch. */
        val name: String,
        val product: Full_product_name_t? = null
    ) {

        init {
            require(name.isNotEmpty()) { "name length < minimum 1 - ${name.length}" }
        }
    }

    /** Describes the characteristics of the labeled branch. */
    enum class Category3 {
        architecture,
        host_name,
        language,
        legacy,
        patch_level,
        product_family,
        product_name,
        product_version,
        product_version_range,
        service_pack,
        specification,
        vendor
    }

    data class Full_product_name_t(
        /**
         * The value should be the product’s full canonical name, including version number and other
         * attributes, as it would be used in a human-friendly document.
         */
        val name: String,
        val product_id: String,
        /**
         * Provides at least one method which aids in identifying the product in an asset database.
         */
        val product_identification_helper: Product_identification_helper? = null
    ) {

        init {
            require(name.isNotEmpty()) { "name length < minimum 1 - ${name.length}" }
            require(product_id.isNotEmpty()) {
                "product_id length < minimum 1 - ${product_id.length}"
            }
        }
    }

    /** Provides at least one method which aids in identifying the product in an asset database. */
    data class Product_identification_helper(
        /**
         * The Common Platform Enumeration (CPE) attribute refers to a method for naming platforms
         * external to this specification.
         */
        val cpe: String? = null,
        /** Contains a list of cryptographic hashes usable to identify files. */
        val hashes: List<Hashe>? = null,
        /** Contains a list of full or abbreviated (partial) model numbers. */
        val model_numbers: Set<String>? = null,
        /**
         * The package URL (purl) attribute refers to a method for reliably identifying and locating
         * software packages external to this specification.
         */
        val purl: URI? = null,
        /** Contains a list of URLs where SBOMs for this product can be retrieved. */
        val sbom_urls: List<URI>? = null,
        /** Contains a list of full or abbreviated (partial) serial numbers. */
        val serial_numbers: Set<String>? = null,
        /** Contains a list of full or abbreviated (partial) stock keeping units. */
        val skus: List<String>? = null,
        /**
         * Contains a list of identifiers which are either vendor-specific or derived from a
         * standard not yet supported.
         */
        val x_generic_uris: List<X_generic_uri>? = null
    ) {

        init {
            if (cpe != null) {
                require(cpe.length >= 5) { "cpe length < minimum 5 - ${cpe.length}" }
                require(cg_regex5.containsMatchIn(cpe)) {
                    "cpe does not match pattern $cg_regex5 - $cpe"
                }
            }
            if (hashes != null)
                require(hashes.isNotEmpty()) { "hashes length < minimum 1 - ${hashes.size}" }
            if (model_numbers != null) {
                for (cg_10 in model_numbers) require(cg_10.isNotEmpty()) {
                    "model_numbers item length < minimum 1 - ${cg_10.length}"
                }
                require(model_numbers.isNotEmpty()) {
                    "model_numbers length < minimum 1 - ${model_numbers.size}"
                }
            }
            if (sbom_urls != null)
                require(sbom_urls.isNotEmpty()) {
                    "sbom_urls length < minimum 1 - ${sbom_urls.size}"
                }
            if (serial_numbers != null) {
                for (cg_12 in serial_numbers) require(cg_12.isNotEmpty()) {
                    "serial_numbers item length < minimum 1 - ${cg_12.length}"
                }
                require(serial_numbers.isNotEmpty()) {
                    "serial_numbers length < minimum 1 - ${serial_numbers.size}"
                }
            }
            if (skus != null) {
                for (cg_13 in skus) require(cg_13.isNotEmpty()) {
                    "skus item length < minimum 1 - ${cg_13.length}"
                }
                require(skus.isNotEmpty()) { "skus length < minimum 1 - ${skus.size}" }
            }
            if (x_generic_uris != null)
                require(x_generic_uris.isNotEmpty()) {
                    "x_generic_uris length < minimum 1 - ${x_generic_uris.size}"
                }
        }
    }

    /** Contains all information to identify a file based on its cryptographic hash values. */
    data class Hashe(
        /** Contains a list of cryptographic hashes for this file. */
        val file_hashes: List<File_hashe>,
        /** Contains the name of the file which is identified by the hash values. */
        val filename: String
    ) {

        init {
            require(file_hashes.isNotEmpty()) {
                "file_hashes length < minimum 1 - ${file_hashes.size}"
            }
            require(filename.isNotEmpty()) { "filename length < minimum 1 - ${filename.length}" }
        }
    }

    /** Contains one hash value and algorithm of the file to be identified. */
    data class File_hashe(
        /** Contains the name of the cryptographic hash algorithm used to calculate the value. */
        val algorithm: String = "sha256",
        /** Contains the cryptographic hash value in hexadecimal representation. */
        val value: String
    ) {

        init {
            require(algorithm.isNotEmpty()) { "algorithm length < minimum 1 - ${algorithm.length}" }
            require(value.length >= 32) { "value length < minimum 32 - ${value.length}" }
            require(cg_regex6.containsMatchIn(value)) {
                "value does not match pattern $cg_regex6 - $value"
            }
        }
    }

    /**
     * Provides a generic extension point for any identifier which is either vendor-specific or
     * derived from a standard not yet supported.
     */
    data class X_generic_uri(
        /**
         * Refers to a URL which provides the name and knowledge about the specification used or is
         * the namespace in which these values are valid.
         */
        val namespace: URI,
        /** Contains the identifier itself. */
        val uri: URI
    )

    /**
     * Defines a new logical group of products that can then be referred to in other parts of the
     * document to address a group of products with a single identifier.
     */
    data class Product_group(
        val group_id: String,
        /** Lists the product_ids of those products which known as one group in the document. */
        val product_ids: Set<String>,
        /** Gives a short, optional description of the group. */
        val summary: String? = null
    ) {

        init {
            require(group_id.isNotEmpty()) { "group_id length < minimum 1 - ${group_id.length}" }
            for (cg_24 in product_ids) require(cg_24.isNotEmpty()) {
                "product_ids item length < minimum 1 - ${cg_24.length}"
            }
            require(product_ids.size >= 2) {
                "product_ids length < minimum 2 - ${product_ids.size}"
            }
            if (summary != null)
                require(summary.isNotEmpty()) { "summary length < minimum 1 - ${summary.length}" }
        }
    }

    /**
     * Establishes a link between two existing full_product_name_t elements, allowing the document
     * producer to define a combination of two products that form a new full_product_name entry.
     */
    data class Relationship(
        /** Defines the category of relationship for the referenced component. */
        val category: Category4,
        val full_product_name: Full_product_name_t,
        /**
         * Holds a Product ID that refers to the Full Product Name element, which is referenced as
         * the first element of the relationship.
         */
        val product_reference: String,
        /**
         * Holds a Product ID that refers to the Full Product Name element, which is referenced as
         * the second element of the relationship.
         */
        val relates_to_product_reference: String
    ) {

        init {
            require(product_reference.isNotEmpty()) {
                "product_reference length < minimum 1 - ${product_reference.length}"
            }
            require(relates_to_product_reference.isNotEmpty()) {
                "relates_to_product_reference length < minimum 1 - ${relates_to_product_reference.length}"
            }
        }
    }

    /** Defines the category of relationship for the referenced component. */
    enum class Category4 {
        default_component_of,
        external_component_of,
        installed_on,
        installed_with,
        optional_component_of
    }

    /**
     * Is a container for the aggregation of all fields that are related to a single vulnerability
     * in the document.
     */
    data class Vulnerabilitie(
        /** Contains a list of acknowledgment elements associated with this vulnerability item. */
        val acknowledgments: List<Acknowledgments_t>? = null,
        /**
         * Holds the MITRE standard Common Vulnerabilities and Exposures (CVE) tracking number for
         * the vulnerability.
         */
        val cve: String? = null,
        /**
         * Holds the MITRE standard Common Weakness Enumeration (CWE) for the weakness associated.
         */
        val cwe: Cwe? = null,
        /** Holds the date and time the vulnerability was originally discovered. */
        val discovery_date: OffsetDateTime? = null,
        /** Contains a list of machine readable flags. */
        val flags: Set<Flag>? = null,
        /**
         * Represents a list of unique labels or tracking IDs for the vulnerability (if such
         * information exists).
         */
        val ids: Set<Id>? = null,
        /** Contains a list of involvements. */
        val involvements: Set<Involvement>? = null,
        /** Holds notes associated with this vulnerability item. */
        val notes: List<Notes_t>? = null,
        /**
         * Contains different lists of product_ids which provide details on the status of the
         * referenced product related to the current vulnerability.
         */
        val product_status: Product_status? = null,
        /** Holds a list of references associated with this vulnerability item. */
        val references: List<References_t>? = null,
        /** Holds the date and time the vulnerability was originally released into the wild. */
        val release_date: OffsetDateTime? = null,
        /** Contains a list of remediations. */
        val remediations: List<Remediation>? = null,
        /** Contains score objects for the current vulnerability. */
        val scores: List<Score>? = null,
        /** Contains information about a vulnerability that can change with time. */
        val threats: List<Threat>? = null,
        /**
         * Gives the document producer the ability to apply a canonical name or title to the
         * vulnerability.
         */
        val title: String? = null
    ) {

        init {
            if (acknowledgments != null)
                require(acknowledgments.isNotEmpty()) {
                    "acknowledgments length < minimum 1 - ${acknowledgments.size}"
                }
            if (cve != null)
                require(cg_regex7.containsMatchIn(cve)) {
                    "cve does not match pattern $cg_regex7 - $cve"
                }
            if (flags != null)
                require(flags.isNotEmpty()) { "flags length < minimum 1 - ${flags.size}" }
            if (ids != null) require(ids.isNotEmpty()) { "ids length < minimum 1 - ${ids.size}" }
            if (involvements != null)
                require(involvements.isNotEmpty()) {
                    "involvements length < minimum 1 - ${involvements.size}"
                }
            if (notes != null)
                require(notes.isNotEmpty()) { "notes length < minimum 1 - ${notes.size}" }
            if (references != null)
                require(references.isNotEmpty()) {
                    "references length < minimum 1 - ${references.size}"
                }
            if (remediations != null)
                require(remediations.isNotEmpty()) {
                    "remediations length < minimum 1 - ${remediations.size}"
                }
            if (scores != null)
                require(scores.isNotEmpty()) { "scores length < minimum 1 - ${scores.size}" }
            if (threats != null)
                require(threats.isNotEmpty()) { "threats length < minimum 1 - ${threats.size}" }
            if (title != null)
                require(title.isNotEmpty()) { "title length < minimum 1 - ${title.length}" }
        }
    }

    /** Holds the MITRE standard Common Weakness Enumeration (CWE) for the weakness associated. */
    data class Cwe(
        /** Holds the ID for the weakness associated. */
        val id: String,
        /** Holds the full name of the weakness as given in the CWE specification. */
        val name: String
    ) {

        init {
            require(cg_regex8.containsMatchIn(id)) { "id does not match pattern $cg_regex8 - $id" }
            require(name.isNotEmpty()) { "name length < minimum 1 - ${name.length}" }
        }
    }

    /**
     * Contains product specific information in regard to this vulnerability as a single machine
     * readable flag.
     */
    data class Flag(
        /** Contains the date when assessment was done or the flag was assigned. */
        val date: OffsetDateTime? = null,
        val group_ids: Set<String>? = null,
        /** Specifies the machine readable label. */
        val label: Label1,
        val product_ids: Set<String>? = null
    ) {

        init {
            if (group_ids != null) {
                for (cg_38 in group_ids) require(cg_38.isNotEmpty()) {
                    "group_ids item length < minimum 1 - ${cg_38.length}"
                }
                require(group_ids.isNotEmpty()) {
                    "group_ids length < minimum 1 - ${group_ids.size}"
                }
            }
            if (product_ids != null) {
                for (cg_39 in product_ids) require(cg_39.isNotEmpty()) {
                    "product_ids item length < minimum 1 - ${cg_39.length}"
                }
                require(product_ids.isNotEmpty()) {
                    "product_ids length < minimum 1 - ${product_ids.size}"
                }
            }
        }
    }

    /** Specifies the machine readable label. */
    enum class Label1 {
        component_not_present,
        inline_mitigations_already_exist,
        vulnerable_code_cannot_be_controlled_by_adversary,
        vulnerable_code_not_in_execute_path,
        vulnerable_code_not_present
    }

    /** Contains a single unique label or tracking ID for the vulnerability. */
    data class Id(
        /** Indicates the name of the vulnerability tracking or numbering system. */
        val system_name: String,
        /** Is unique label or tracking ID for the vulnerability (if such information exists). */
        val text: String
    ) {

        init {
            require(system_name.isNotEmpty()) {
                "system_name length < minimum 1 - ${system_name.length}"
            }
            require(text.isNotEmpty()) { "text length < minimum 1 - ${text.length}" }
        }
    }

    /**
     * Is a container, that allows the document producers to comment on the level of involvement (or
     * engagement) of themselves or third parties in the vulnerability identification, scoping, and
     * remediation process.
     */
    data class Involvement(
        /** Holds the date and time of the involvement entry. */
        val date: OffsetDateTime? = null,
        /** Defines the category of the involved party. */
        val party: Party,
        /** Defines contact status of the involved party. */
        val status: Status1,
        /** Contains additional context regarding what is going on. */
        val summary: String? = null
    ) {

        init {
            if (summary != null)
                require(summary.isNotEmpty()) { "summary length < minimum 1 - ${summary.length}" }
        }
    }

    /** Defines the category of the involved party. */
    enum class Party {
        coordinator,
        discoverer,
        other,
        user,
        vendor
    }

    /** Defines contact status of the involved party. */
    enum class Status1 {
        completed,
        contact_attempted,
        disputed,
        in_progress,
        not_contacted,
        open
    }

    /**
     * Contains different lists of product_ids which provide details on the status of the referenced
     * product related to the current vulnerability.
     */
    data class Product_status(
        /**
         * These are the first versions of the releases known to be affected by the vulnerability.
         */
        val first_affected: Set<String>? = null,
        /**
         * These versions contain the first fix for the vulnerability but may not be the recommended
         * fixed versions.
         */
        val first_fixed: Set<String>? = null,
        /**
         * These versions contain a fix for the vulnerability but may not be the recommended fixed
         * versions.
         */
        val fixed: Set<String>? = null,
        /** These versions are known to be affected by the vulnerability. */
        val known_affected: Set<String>? = null,
        /** These versions are known not to be affected by the vulnerability. */
        val known_not_affected: Set<String>? = null,
        /**
         * These are the last versions in a release train known to be affected by the vulnerability.
         * Subsequently released versions would contain a fix for the vulnerability.
         */
        val last_affected: Set<String>? = null,
        /**
         * These versions have a fix for the vulnerability and are the vendor-recommended versions
         * for fixing the vulnerability.
         */
        val recommended: Set<String>? = null,
        /**
         * It is not known yet whether these versions are or are not affected by the vulnerability.
         * However, it is still under investigation - the result will be provided in a later release
         * of the document.
         */
        val under_investigation: Set<String>? = null
    ) {

        init {
            if (first_affected != null) {
                for (cg_43 in first_affected) require(cg_43.isNotEmpty()) {
                    "first_affected item length < minimum 1 - ${cg_43.length}"
                }
                require(first_affected.isNotEmpty()) {
                    "first_affected length < minimum 1 - ${first_affected.size}"
                }
            }
            if (first_fixed != null) {
                for (cg_44 in first_fixed) require(cg_44.isNotEmpty()) {
                    "first_fixed item length < minimum 1 - ${cg_44.length}"
                }
                require(first_fixed.isNotEmpty()) {
                    "first_fixed length < minimum 1 - ${first_fixed.size}"
                }
            }
            if (fixed != null) {
                for (cg_45 in fixed) require(cg_45.isNotEmpty()) {
                    "fixed item length < minimum 1 - ${cg_45.length}"
                }
                require(fixed.isNotEmpty()) { "fixed length < minimum 1 - ${fixed.size}" }
            }
            if (known_affected != null) {
                for (cg_46 in known_affected) require(cg_46.isNotEmpty()) {
                    "known_affected item length < minimum 1 - ${cg_46.length}"
                }
                require(known_affected.isNotEmpty()) {
                    "known_affected length < minimum 1 - ${known_affected.size}"
                }
            }
            if (known_not_affected != null) {
                for (cg_47 in known_not_affected) require(cg_47.isNotEmpty()) {
                    "known_not_affected item length < minimum 1 - ${cg_47.length}"
                }
                require(known_not_affected.isNotEmpty()) {
                    "known_not_affected length < minimum 1 - ${known_not_affected.size}"
                }
            }
            if (last_affected != null) {
                for (cg_48 in last_affected) require(cg_48.isNotEmpty()) {
                    "last_affected item length < minimum 1 - ${cg_48.length}"
                }
                require(last_affected.isNotEmpty()) {
                    "last_affected length < minimum 1 - ${last_affected.size}"
                }
            }
            if (recommended != null) {
                for (cg_49 in recommended) require(cg_49.isNotEmpty()) {
                    "recommended item length < minimum 1 - ${cg_49.length}"
                }
                require(recommended.isNotEmpty()) {
                    "recommended length < minimum 1 - ${recommended.size}"
                }
            }
            if (under_investigation != null) {
                for (cg_50 in under_investigation) require(cg_50.isNotEmpty()) {
                    "under_investigation item length < minimum 1 - ${cg_50.length}"
                }
                require(under_investigation.isNotEmpty()) {
                    "under_investigation length < minimum 1 - ${under_investigation.size}"
                }
            }
        }
    }

    /** Specifies details on how to handle (and presumably, fix) a vulnerability. */
    data class Remediation(
        /** Specifies the category which this remediation belongs to. */
        val category: Category5,
        /** Contains the date from which the remediation is available. */
        val date: OffsetDateTime? = null,
        /** Contains a thorough human-readable discussion of the remediation. */
        val details: String,
        /** Contains a list of entitlements. */
        val entitlements: List<String>? = null,
        val group_ids: Set<String>? = null,
        val product_ids: Set<String>? = null,
        /**
         * Provides information on category of restart is required by this remediation to become
         * effective.
         */
        val restart_required: Restart_required? = null,
        /** Contains the URL where to obtain the remediation. */
        val url: URI? = null
    ) {

        init {
            require(details.isNotEmpty()) { "details length < minimum 1 - ${details.length}" }
            if (entitlements != null) {
                for (cg_53 in entitlements) require(cg_53.isNotEmpty()) {
                    "entitlements item length < minimum 1 - ${cg_53.length}"
                }
                require(entitlements.isNotEmpty()) {
                    "entitlements length < minimum 1 - ${entitlements.size}"
                }
            }
            if (group_ids != null) {
                for (cg_54 in group_ids) require(cg_54.isNotEmpty()) {
                    "group_ids item length < minimum 1 - ${cg_54.length}"
                }
                require(group_ids.isNotEmpty()) {
                    "group_ids length < minimum 1 - ${group_ids.size}"
                }
            }
            if (product_ids != null) {
                for (cg_55 in product_ids) require(cg_55.isNotEmpty()) {
                    "product_ids item length < minimum 1 - ${cg_55.length}"
                }
                require(product_ids.isNotEmpty()) {
                    "product_ids length < minimum 1 - ${product_ids.size}"
                }
            }
        }
    }

    /** Specifies the category which this remediation belongs to. */
    enum class Category5 {
        mitigation,
        no_fix_planned,
        none_available,
        vendor_fix,
        workaround
    }

    /**
     * Provides information on category of restart is required by this remediation to become
     * effective.
     */
    data class Restart_required(
        /**
         * Specifies what category of restart is required by this remediation to become effective.
         */
        val category: Category6,
        /**
         * Provides additional information for the restart. This can include details on procedures,
         * scope or impact.
         */
        val details: String? = null
    ) {

        init {
            if (details != null)
                require(details.isNotEmpty()) { "details length < minimum 1 - ${details.length}" }
        }
    }

    /** Specifies what category of restart is required by this remediation to become effective. */
    enum class Category6 {
        connected,
        dependencies,
        machine,
        none,
        parent,
        service,
        system,
        vulnerable_component,
        zone
    }

    /**
     * Specifies information about (at least one) score of the vulnerability and for which products
     * the given value applies.
     */
    data class Score(
        val cvss_v2: Cvss_v2? = null,
        val cvss_v3: Any? = null,
        val products: Set<String>
    ) {

        init {
            for (cg_57 in products) require(cg_57.isNotEmpty()) {
                "products item length < minimum 1 - ${cg_57.length}"
            }
            require(products.isNotEmpty()) { "products length < minimum 1 - ${products.size}" }
        }
    }

    data class Cvss_v2(
        /** CVSS Version */
        val version: String,
        val vectorString: String,
        val accessVector: AccessVectorType? = null,
        val accessComplexity: AccessComplexityType? = null,
        val authentication: AuthenticationType? = null,
        val confidentialityImpact: CiaType? = null,
        val integrityImpact: CiaType? = null,
        val availabilityImpact: CiaType? = null,
        val baseScore: BigDecimal,
        val exploitability: ExploitabilityType? = null,
        val remediationLevel: RemediationLevelType? = null,
        val reportConfidence: ReportConfidenceType? = null,
        val temporalScore: BigDecimal? = null,
        val collateralDamagePotential: CollateralDamagePotentialType? = null,
        val targetDistribution: TargetDistributionType? = null,
        val confidentialityRequirement: CiaRequirementType? = null,
        val integrityRequirement: CiaRequirementType? = null,
        val availabilityRequirement: CiaRequirementType? = null,
        val environmentalScore: BigDecimal? = null
    ) {

        init {
            require(version in cg_array1) { "version not in enumerated values - $version" }
            require(cg_regex9.containsMatchIn(vectorString)) {
                "vectorString does not match pattern $cg_regex9 - $vectorString"
            }
            require(baseScore in cg_dec10..cg_dec11) { "baseScore not in range 0..10 - $baseScore" }
            if (temporalScore != null)
                require(temporalScore in cg_dec10..cg_dec11) {
                    "temporalScore not in range 0..10 - $temporalScore"
                }
            if (environmentalScore != null)
                require(environmentalScore in cg_dec10..cg_dec11) {
                    "environmentalScore not in range 0..10 - $environmentalScore"
                }
        }
    }

    enum class AccessVectorType {
        NETWORK,
        ADJACENT_NETWORK,
        LOCAL
    }

    enum class AccessComplexityType {
        HIGH,
        MEDIUM,
        LOW
    }

    enum class AuthenticationType {
        MULTIPLE,
        SINGLE,
        NONE
    }

    enum class CiaType {
        NONE,
        PARTIAL,
        COMPLETE
    }

    enum class ExploitabilityType {
        UNPROVEN,
        PROOF_OF_CONCEPT,
        FUNCTIONAL,
        HIGH,
        NOT_DEFINED
    }

    enum class RemediationLevelType {
        OFFICIAL_FIX,
        TEMPORARY_FIX,
        WORKAROUND,
        UNAVAILABLE,
        NOT_DEFINED
    }

    enum class ReportConfidenceType {
        UNCONFIRMED,
        UNCORROBORATED,
        CONFIRMED,
        NOT_DEFINED
    }

    enum class CollateralDamagePotentialType {
        NONE,
        LOW,
        LOW_MEDIUM,
        MEDIUM_HIGH,
        HIGH,
        NOT_DEFINED
    }

    enum class TargetDistributionType {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        NOT_DEFINED
    }

    enum class CiaRequirementType {
        LOW,
        MEDIUM,
        HIGH,
        NOT_DEFINED
    }

    /**
     * Contains the vulnerability kinetic information. This information can change as the
     * vulnerability ages and new information becomes available.
     */
    data class Threat(
        /** Categorizes the threat according to the rules of the specification. */
        val category: Category7,
        /** Contains the date when the assessment was done or the threat appeared. */
        val date: OffsetDateTime? = null,
        /** Represents a thorough human-readable discussion of the threat. */
        val details: String,
        val group_ids: Set<String>? = null,
        val product_ids: Set<String>? = null
    ) {

        init {
            require(details.isNotEmpty()) { "details length < minimum 1 - ${details.length}" }
            if (group_ids != null) {
                for (cg_59 in group_ids) require(cg_59.isNotEmpty()) {
                    "group_ids item length < minimum 1 - ${cg_59.length}"
                }
                require(group_ids.isNotEmpty()) {
                    "group_ids length < minimum 1 - ${group_ids.size}"
                }
            }
            if (product_ids != null) {
                for (cg_60 in product_ids) require(cg_60.isNotEmpty()) {
                    "product_ids item length < minimum 1 - ${cg_60.length}"
                }
                require(product_ids.isNotEmpty()) {
                    "product_ids length < minimum 1 - ${product_ids.size}"
                }
            }
        }
    }

    /** Categorizes the threat according to the rules of the specification. */
    enum class Category7 {
        exploit_status,
        impact,
        target_set
    }

    companion object {
        private val cg_regex0 = Regex("^[^\\s\\-_\\.](.*[^\\s\\-_\\.])?\$")
        private val cg_array1 = setOf("2.0")
        private val cg_regex2 =
            Regex(
                "^(([A-Za-z]{2,3}(-[A-Za-z]{3}(-[A-Za-z]{3}){0,2})?|[A-Za-z]{4,8})(-[A-Za-z]{4})?(-([A-Za-z]{2}|[0-9]{3}))?(-([A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*(-[A-WY-Za-wy-z0-9](-[A-Za-z0-9]{2,8})+)*(-[Xx](-[A-Za-z0-9]{1,8})+)?|[Xx](-[A-Za-z0-9]{1,8})+|[Ii]-[Dd][Ee][Ff][Aa][Uu][Ll][Tt]|[Ii]-[Mm][Ii][Nn][Gg][Oo])\$"
            )
        private val cg_regex3 = Regex("^[\\S](.*[\\S])?\$")
        private val cg_regex4 =
            Regex(
                "^(0|[1-9][0-9]*)\$|^((0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?)\$"
            )
        private val cg_regex5 =
            Regex(
                "^(cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#\\\$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|\\}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#\\\$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|\\}~]))+(\\?*|\\*?))|[\\*\\-])){4})|([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\\._\\-~%]*){0,6})\$"
            )
        private val cg_regex6 = Regex("^[0-9a-fA-F]{32,}\$")
        private val cg_regex7 = Regex("^CVE-[0-9]{4}-[0-9]{4,}\$")
        private val cg_regex8 = Regex("^CWE-[1-9]\\d{0,5}\$")
        private val cg_regex9 =
            Regex(
                "^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))\$"
            )
        private val cg_dec10 = BigDecimal.ZERO
        private val cg_dec11 = BigDecimal("10")
    }
}
