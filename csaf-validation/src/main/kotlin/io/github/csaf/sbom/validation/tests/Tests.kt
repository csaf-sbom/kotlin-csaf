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
package io.github.csaf.sbom.validation.tests

import com.github.packageurl.MalformedPackageURLException
import com.github.packageurl.PackageURL
import io.github.csaf.sbom.cvss.MetricValue
import io.github.csaf.sbom.cvss.v3.CvssV3Calculation
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.Test
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationNotApplicable
import io.github.csaf.sbom.validation.ValidationResult
import io.github.csaf.sbom.validation.ValidationSuccessful
import io.github.csaf.sbom.validation.merge
import io.github.csaf.sbom.validation.profiles.InformationalAdvisory
import io.github.csaf.sbom.validation.profiles.SecurityAdvisory
import io.github.csaf.sbom.validation.profiles.SecurityIncidentResponse
import io.github.csaf.sbom.validation.profiles.VEX
import io.github.csaf.sbom.validation.profiles.officialProfiles
import kotlin.collections.flatMap
import kotlin.reflect.KProperty1
import net.swiftzer.semver.SemVer

/**
 * Mandatory tests as defined in
 * [Section 6.1](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61-mandatory-tests).
 */
val mandatoryTests =
    listOf(
        Test611MissingDefinitionOfProductID,
        Test612MultipleDefinitionOfProductID,
        Test613CircularDefinitionOfProductID,
        Test614MissingDefinitionOfProductGroupID,
        Test615MultipleDefinitionOfProductGroupID,
        Test616ContradictingProductStatus,
        Test617MultipleScoresWithSameVersionPerProduct,
        Test618InvalidCVSS,
        Test619InvalidCVSSComputation,
        Test6110InconsistentCVSS,
        Test6111CWE,
        Test6112Language,
        Test6113PURL,
        Test6114SortedRevisionHistory,
        Test6115Translator,
        Test6116LatestDocumentVersion,
        Test6117DocumentStatusDraft,
        Test6118ReleasedRevisionHistory,
        Test6119RevisionHistoryEntriesForPreReleaseVersions,
        Test6120NonDraftDocumentVersion,
        Test6121MissingItemInRevisionHistory,
        Test6122MultipleDefinitionInRevisionHistory,
        Test6123MultipleUseOfSameCVE,
        Test6124MultipleDefinitionInInvolvements,
        Test6125MultipleUseOfSameHashAlgorithm,
        Test6126ProhibitedDocumentCategoryName,
        Test61271DocumentNotes,
        Test61272DocumentReferences,
        Test61273Vulnerabilities,
        Test61274ProductTree,
        Test61275VulnerabilityNotes,
        Test61276ProductStatus,
        Test61277VEXProductStatus,
        Test61278VulnerabilityID,
        Test61279ImpactStatement,
        Test612710ActionStatement,
        Test612711Vulnerabilities,
        Test6128Translation,
        Test6129RemediationWithoutProductReference,
        Test6130MixedIntegerAndSemanticVersioning,
        Test6131VersionRangeInProductVersion,
        Test6132FlatWithoutProductReference,
        Test6133MultipleFlagsWithVEXJustificationCodesPerProduct
    )

/**
 * Optional tests as defined in
 * [Section 6.2](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#62-optional-tests).
 */
val optionalTests =
    listOf(
        Test621UnusedDefinitionOfProductID,
    )

/**
 * Informative tests as defined in
 * [Section 6.3](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#63-informative-test).
 */
val informativeTests = listOf<Test>()

/** Executes all tests in this list of [Test] objects. */
fun List<Test>.test(doc: Csaf): ValidationResult {
    return this.map { it.test(doc) }.merge()
}

/**
 * Implementation of
 * [Test 6.1.1](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#611-missing-definition-of-product-id).
 */
object Test611MissingDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProductDefinitions()
        val references = doc.gatherProductReferences()

        val notDefined = references.subtract(definitions.toSet())

        return if (notDefined.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are not defined: ${notDefined.joinToString(",")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.2](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#612-multiple-definition-of-product-id).
 */
object Test612MultipleDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProductDefinitions()

        val duplicates = definitions.duplicates()

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are duplicate: ${duplicates.keys.joinToString(",")}")
            )
        }
    }
}

private fun <T> List<T>?.duplicates(): Map<T, Int> {
    return if (this == null) {
        mapOf()
    } else {
        groupingBy { it }.eachCount().filter { it.value > 1 }
    }
}

/**
 * Implementation of
 * [Test 6.1.3](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#613-circular-definition-of-product-id).
 */
object Test613CircularDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val circles = mutableSetOf<String>()

        for (relationship in doc.product_tree?.relationships ?: listOf()) {
            val definedId = relationship.full_product_name.product_id
            val notAllowed =
                listOf(relationship.product_reference, relationship.relates_to_product_reference)
            if (definedId in notAllowed) {
                circles += definedId
            }
        }

        return if (circles.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are defined in circles: ${circles.joinToString(",")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.4](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#614-missing-definition-of-product-group-id).
 */
object Test614MissingDefinitionOfProductGroupID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProductGroups()
        val references = doc.gatherProductGroupReferences()

        val notDefined = references.subtract(definitions.toSet())

        return if (notDefined.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are not defined: ${notDefined.joinToString(",")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.5](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#615-multiple-definition-of-product-group-id)
 */
object Test615MultipleDefinitionOfProductGroupID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProductGroups()

        val duplicates = definitions.duplicates()

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are duplicate: ${duplicates.keys.joinToString(",")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.6](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#616-contradicting-product-status).
 */
object Test616ContradictingProductStatus : Test {
    override fun test(doc: Csaf): ValidationResult {
        val contradicted = mutableSetOf<String>()

        for (vulnerability in doc.vulnerabilities ?: listOf()) {
            val affected =
                vulnerability.product_status?.first_affected +
                    vulnerability.product_status?.known_affected +
                    vulnerability.product_status?.last_affected
            val notAffected = vulnerability.product_status?.known_not_affected ?: setOf()
            val fixed =
                vulnerability.product_status?.first_fixed + vulnerability.product_status?.fixed
            val underInvestigation = vulnerability.product_status?.under_investigation ?: setOf()

            contradicted += affected.intersect(notAffected)
            contradicted += affected.intersect(fixed)
            contradicted += affected.intersect(underInvestigation)
            contradicted += notAffected.intersect(fixed)
            contradicted += notAffected.intersect(underInvestigation)
            contradicted += fixed.intersect(underInvestigation)
        }

        return if (contradicted.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The following IDs have contradicting statuses: ${contradicted.joinToString(",")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.7](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#617-multiple-scores-with-same-version-per-product).
 */
object Test617MultipleScoresWithSameVersionPerProduct : Test {
    override fun test(doc: Csaf): ValidationResult {
        val multiples = mutableSetOf<String>()

        for (vulnerability in doc.vulnerabilities ?: listOf()) {
            // Gather a map of product_id => list of cvss_version
            val productScoreVersions = mutableMapOf<String, MutableList<String>>()
            for (score in vulnerability.scores ?: listOf()) {
                score.products.forEach {
                    val versions = productScoreVersions.computeIfAbsent(it) { mutableListOf() }
                    versions += score.cvss_v3?.version
                    versions += score.cvss_v2?.version
                }
            }

            multiples +=
                productScoreVersions
                    .filter {
                        // We need to look for potential duplicates in the versions
                        val versions = it.value
                        val duplicates = versions.duplicates()

                        duplicates.isNotEmpty()
                    }
                    .map { it.key }
        }

        return if (multiples.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs have multiple scores: ${multiples.joinToString(",")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.8](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#618-invalid-cvss).
 */
object Test618InvalidCVSS : Test {
    override fun test(doc: Csaf): ValidationResult {
        // This is already ensured by our JSON schema validation during the creation of the Csaf
        // object.
        return ValidationSuccessful
    }
}

val test619V3PropertiesMap =
    mapOf<KProperty1<Csaf.CvssV3, Any?>, KProperty1<CvssV3Calculation, Any>>(
        Csaf.CvssV3::baseScore to CvssV3Calculation::baseScore,
        Csaf.CvssV3::baseSeverity to CvssV3Calculation::baseSeverity,
        Csaf.CvssV3::temporalScore to CvssV3Calculation::temporalScore,
        Csaf.CvssV3::temporalSeverity to CvssV3Calculation::temporalSeverity,
        Csaf.CvssV3::environmentalScore to CvssV3Calculation::environmentalScore,
        Csaf.CvssV3::environmentalSeverity to CvssV3Calculation::environmentalSeverity,
    )

/**
 * Implementation of
 * [Test 6.1.9](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#619-invalid-cvss-computation).
 */
object Test619InvalidCVSSComputation : Test {
    override fun test(doc: Csaf): ValidationResult {
        val invalids = mutableSetOf<Pair<String, Pair<Any?, Any>>>()
        for (score in doc.vulnerabilities?.flatMap { it.scores ?: listOf() } ?: listOf()) {
            // TODO(oxisto): CVSS2

            score.cvss_v3?.let {
                // (Re)-Calculate the score
                val calc = CvssV3Calculation.fromVectorString(it.vectorString)

                // Check the following properties for validity
                for (entry in test619V3PropertiesMap) {
                    val documentValue = entry.key.get(it)
                    val calculatedValue = entry.value.get(calc)

                    // Compare the values. Since it is allowed to skip values in the CSAF document,
                    // we only compare non-null values
                    if (documentValue != null && documentValue != calculatedValue) {
                        invalids += Pair(entry.key.name, Pair(documentValue, calculatedValue))
                    }
                }
            }
        }

        return if (invalids.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The following properties are invalid: ${invalids.map{ "${it.first}: ${it.second.first} != ${it.second.second}"}.joinToString(", ")}"
                )
            )
        }
    }
}

val test6110PropertiesMap =
    mapOf<KProperty1<Csaf.CvssV3, Any?>, KProperty1<CvssV3Calculation, MetricValue<*>>>(
        Csaf.CvssV3::attackVector to CvssV3Calculation::attackVector,
        Csaf.CvssV3::attackComplexity to CvssV3Calculation::attackComplexity,
        Csaf.CvssV3::privilegesRequired to CvssV3Calculation::privilegesRequired,
        Csaf.CvssV3::userInteraction to CvssV3Calculation::userInteraction,
        Csaf.CvssV3::scope to CvssV3Calculation::scope,
        Csaf.CvssV3::confidentialityImpact to CvssV3Calculation::confidentialityImpact,
        Csaf.CvssV3::integrityImpact to CvssV3Calculation::integrityImpact,
        Csaf.CvssV3::availabilityImpact to CvssV3Calculation::availabilityImpact,
        Csaf.CvssV3::exploitCodeMaturity to CvssV3Calculation::exploitCodeMaturity,
        Csaf.CvssV3::remediationLevel to CvssV3Calculation::remediationLevel,
        Csaf.CvssV3::confidentialityRequirement to CvssV3Calculation::confidentialityRequirement,
        Csaf.CvssV3::integrityRequirement to CvssV3Calculation::integrityRequirement,
        Csaf.CvssV3::availabilityRequirement to CvssV3Calculation::availabilityRequirement,
        Csaf.CvssV3::modifiedAttackVector to CvssV3Calculation::modifiedAttackVector,
        Csaf.CvssV3::modifiedAttackComplexity to CvssV3Calculation::modifiedAttackComplexity,
        Csaf.CvssV3::modifiedPrivilegesRequired to CvssV3Calculation::modifiedPrivilegesRequired,
        Csaf.CvssV3::modifiedUserInteraction to CvssV3Calculation::modifiedUserInteraction,
        Csaf.CvssV3::modifiedScope to CvssV3Calculation::modifiedScope,
        Csaf.CvssV3::modifiedConfidentialityImpact to
            CvssV3Calculation::modifiedConfidentialityImpact,
        Csaf.CvssV3::modifiedIntegrityImpact to CvssV3Calculation::modifiedIntegrityImpact,
        Csaf.CvssV3::modifiedAvailabilityImpact to CvssV3Calculation::modifiedAvailabilityImpact
    )

/**
 * Implementation of
 * [Test 6.1.10](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6110-inconsistent-cvss).
 */
object Test6110InconsistentCVSS : Test {
    override fun test(doc: Csaf): ValidationResult {
        val inconsistencies = mutableSetOf<Pair<String, Pair<Any?, Any>>>()
        for (score in doc.vulnerabilities?.flatMap { it.scores ?: listOf() } ?: listOf()) {
            // TODO(oxisto): CVSS2

            score.cvss_v3?.let {
                // Parse the vector string
                val calc = CvssV3Calculation.fromVectorString(it.vectorString)

                // Check the following properties for consistency
                for (entry in test6110PropertiesMap) {
                    val documentValue = entry.key.get(it)
                    val calculatedValue = entry.value.get(calc).enumValue

                    // Compare the values. Since it is allowed to skip values in the CSAF document,
                    // we only compare non-null values
                    if (documentValue != null && documentValue != calculatedValue) {
                        inconsistencies +=
                            Pair(entry.key.name, Pair(documentValue, calculatedValue))
                    }
                }
            }
        }

        return if (inconsistencies.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The following properties are inconsistent: ${inconsistencies.map{ "${it.first}: ${it.second.first} != ${it.second.second}"}.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.11](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6111-cwe).
 */
object Test6111CWE : Test {
    override fun test(doc: Csaf): ValidationResult {
        val invalids = mutableSetOf<String>()

        for (vuln in doc.vulnerabilities ?: listOf()) {
            val csafCwe = vuln.cwe
            if (csafCwe == null) {
                continue
            }

            // Look for the ID
            val cwe = weaknesses[csafCwe.id]
            if (cwe == null) {
                invalids += "${csafCwe.id} is invalid"
                continue
            }

            if (cwe.name != csafCwe.name) {
                invalids += "${csafCwe.name} is not the correct name for ${csafCwe.id}"
                continue
            }
        }

        return if (invalids.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Invalid CWE entries: ${invalids.joinToString(", ")}"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.12](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6112-language).
 */
object Test6112Language : Test {
    override fun test(doc: Csaf): ValidationResult {
        val invalids = mutableListOf<String>()

        doc.document.lang?.let {
            if (!it.isLanguage) {
                invalids += it
            }
        }

        doc.document.source_lang?.let {
            if (!it.isLanguage) {
                invalids += it
            }
        }

        return if (invalids.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following languages are not valid: ${invalids.joinToString(", ")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.13](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6113-purl).
 */
object Test6113PURL : Test {
    override fun test(doc: Csaf): ValidationResult {
        val purls = doc.gatherProductURLs()
        val invalids =
            purls.mapNotNull {
                try {
                    PackageURL(it)
                    null
                } catch (ex: MalformedPackageURLException) {
                    ex.message
                }
            }

        return if (invalids.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Invalid PURLs: ${invalids.joinToString(", ")}"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.14](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6114-sorted-revision-history).
 */
object Test6114SortedRevisionHistory : Test {
    override fun test(doc: Csaf): ValidationResult {
        // First, sort items ascending by date (then by number in case the date is the same)
        val sorted =
            doc.document.tracking.revision_history.sortedWith(
                compareBy<Csaf.RevisionHistory> { it.date }
                    .then { a, b -> a.number.compareVersionTo(b.number) }
            )

        // Then, check if it is sorted by number
        val isSortedByNumber =
            sorted
                .asSequence()
                .zipWithNext { a, b -> a.number.compareVersionTo(b.number) < 0 }
                .all { it }
        return if (isSortedByNumber) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The revision history is not sorted by ascending date"))
        }
        println(isSortedByNumber)
    }
}

/**
 * Implementation of
 * [Test 6.1.15](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6115-translator).
 */
object Test6115Translator : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.document.publisher.category != Csaf.Category1.translator) {
            return ValidationNotApplicable
        }

        return if (doc.document.source_lang != null) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The publisher is a translator, but the source language is not present")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.16](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6116-latest-document-version).
 */
object Test6116LatestDocumentVersion : Test {
    override fun test(doc: Csaf): ValidationResult {
        // First, sort items ascending by date (then by number in case the date is the same)
        val sorted =
            doc.document.tracking.revision_history.sortedWith(
                compareBy<Csaf.RevisionHistory> { it.date }
                    .then { a, b -> a.number.compareVersionTo(b.number) }
            )
        val latestVersion = sorted.last().number

        return if (
            latestVersion.equalsVersion(
                doc.document.tracking.version,
                ignoreMetadata = true,
                ignorePreRelease = doc.document.tracking.status == Csaf.Status.draft
            )
        ) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The latest version should be $latestVersion but is ${doc.document.tracking.version}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.17](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6117-document-status-draft).
 */
object Test6117DocumentStatusDraft : Test {
    override fun test(doc: Csaf): ValidationResult {
        return if (
            !doc.document.tracking.version.isVersionZeroOrPreRelease ||
                (doc.document.tracking.status == Csaf.Status.draft)
        ) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The latest version is a pre-release or \"zero\" version (${doc.document.tracking.version}) but the document status is ${doc.document.tracking.status}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.18](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6118-released-revision-history).
 */
object Test6118ReleasedRevisionHistory : Test {
    override fun test(doc: Csaf): ValidationResult {
        val nonDraftStatuses = listOf(Csaf.Status.final, Csaf.Status.interim)
        // Only final or interim documents are applicable
        if (doc.document.tracking.status !in nonDraftStatuses) {
            return ValidationSuccessful
        }

        // Otherwise, we need to check for the revision history
        val zeroVersions =
            doc.document.tracking.revision_history.filter {
                it.number == "0" || SemVer.parseOrNull(it.number)?.major == 0
            }

        return if (zeroVersions.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The document is ${doc.document.tracking.status} but it contains the following revisions: ${zeroVersions.map { it.number }.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.19](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6119-revision-history-entries-for-pre-release-versions).
 */
object Test6119RevisionHistoryEntriesForPreReleaseVersions : Test {
    override fun test(doc: Csaf): ValidationResult {
        val preReleaseVersions =
            doc.document.tracking.revision_history.filter {
                SemVer.parseOrNull(it.number)?.preRelease != null
            }

        return if (preReleaseVersions.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The document contains the following pre-release revisions: ${preReleaseVersions.map { it.number }.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.20](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6120-non-draft-document-version).
 */
object Test6120NonDraftDocumentVersion : Test {
    override fun test(doc: Csaf): ValidationResult {
        val finalStatues = listOf(Csaf.Status.final, Csaf.Status.interim)
        return if (
            (doc.document.tracking.status !in finalStatues) ||
                !doc.document.tracking.version.isPreRelease
        ) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The latest version is a pre-release (${doc.document.tracking.version}) but the document status is ${doc.document.tracking.status}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.21](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6121-missing-item-in-revision-history).
 */
object Test6121MissingItemInRevisionHistory : Test {
    override fun test(doc: Csaf): ValidationResult {
        val startVersions = listOf(0, 1)
        val missing = mutableSetOf<String>()

        // First, sort items ascending by date
        val sortedByDate = doc.document.tracking.revision_history.sortedBy { it.date }

        val first = sortedByDate.first()
        if (first.number.versionOrMajorVersion !in startVersions) {
            return ValidationFailed(
                listOf(
                    "Start version ${first.number} must be either 0 or 1 (or a major version of it)"
                )
            )
        }

        // Check for missing items
        sortedByDate.reduce { prev, current ->
            val prevVersion = prev.number.versionOrMajorVersion
            val expectedVersion = prevVersion + 1
            val currentVersion = current.number.versionOrMajorVersion
            if (expectedVersion != currentVersion && prevVersion != currentVersion) {
                missing += expectedVersion.toString()
            }
            current
        }

        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following versions are missing: ${missing.joinToString(", ")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.22](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6122-multiple-definition-in-revision-history).
 */
object Test6122MultipleDefinitionInRevisionHistory : Test {
    override fun test(doc: Csaf): ValidationResult {
        val versions = doc.document.tracking.revision_history.map { it.number }
        val duplicates = versions.duplicates()

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            return ValidationFailed(
                listOf(
                    "The following versions in the revision history are duplicate: ${duplicates.keys.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.23](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6123-multiple-use-of-same-cve).
 */
object Test6123MultipleUseOfSameCVE : Test {
    override fun test(doc: Csaf): ValidationResult {
        val cves = doc.vulnerabilities?.mapNotNull { it.cve } ?: listOf()
        val duplicates = cves.duplicates()

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            return ValidationFailed(
                listOf(
                    "The following CVE identifiers are duplicate: ${duplicates.keys.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.24](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6124-multiple-definition-in-involvements).
 */
object Test6124MultipleDefinitionInInvolvements : Test {
    override fun test(doc: Csaf): ValidationResult {
        val duplicates =
            doc.vulnerabilities?.flatMap {
                (it.involvements?.map { Pair(it.party, it.date) } ?: listOf()).duplicates().keys
            } ?: listOf()

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            return ValidationFailed(
                listOf(
                    "The following party/date pairs are duplicate: ${duplicates.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.25](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6125-multiple-use-of-same-hash-algorithm).
 */
object Test6125MultipleUseOfSameHashAlgorithm : Test {
    override fun test(doc: Csaf): ValidationResult {
        var hashLists = doc.gatherFileHashLists()
        var duplicates = hashLists.flatMap { it.map { it.algorithm }.duplicates().keys }

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            return ValidationFailed(
                listOf(
                    "The following hash algorithms are duplicate: ${duplicates.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.26](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6126-prohibited-document-category-name).
 */
object Test6126ProhibitedDocumentCategoryName : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.document.category in officialProfiles.keys) {
            return ValidationNotApplicable
        }

        val cleanedCategory = doc.document.category.lowercase().replace("(_-)", "")

        // It is not allowed to match an official profile's name (without csaf_ prefix)
        return if (cleanedCategory !in officialProfiles.keys.map { it.substringAfter("csaf_") }) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The value $cleanedCategory is the name of a profile where the space was replaced with underscores"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.1](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61271-document-notes).
 */
object Test61271DocumentNotes : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is InformationalAdvisory && doc.profile !is SecurityIncidentResponse) {
            return ValidationNotApplicable
        }

        return if (
            doc.document.notes?.any {
                it.category in
                    listOf(
                        Csaf.Category.description,
                        Csaf.Category.details,
                        Csaf.Category.general,
                        Csaf.Category.summary,
                    )
            } == true
        ) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The document notes do not contain an item which has a category of description, details, general or summary"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.2](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61272-document-references).
 */
object Test61272DocumentReferences : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is InformationalAdvisory && doc.profile !is SecurityIncidentResponse) {
            return ValidationNotApplicable
        }

        return if (
            doc.document.references?.any { it.category == Csaf.Category2.external } == true
        ) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The document references do not contain any item which has the category external"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.3](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61273-vulnerabilities).
 */
object Test61273Vulnerabilities : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is InformationalAdvisory) {
            return ValidationNotApplicable
        }

        return if (doc.vulnerabilities == null) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The element /vulnerabilities exists"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.4](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61274-product-tree).
 */
object Test61274ProductTree : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is VEX && doc.profile !is SecurityAdvisory) {
            return ValidationNotApplicable
        }

        return if (doc.product_tree != null) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The element /product_tree does not exist"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.5](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61275-vulnerability-notes).
 */
object Test61275VulnerabilityNotes : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is VEX && doc.profile !is SecurityAdvisory) {
            return ValidationNotApplicable
        }

        val missing = doc.vulnerabilities?.filter { it.notes == null } ?: listOf()

        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The vulnerability item has no notes element"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.6](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61276-product-status).
 */
object Test61276ProductStatus : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is SecurityAdvisory) {
            return ValidationNotApplicable
        }

        val missing = doc.vulnerabilities?.filter { it.product_status == null } ?: listOf()

        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The vulnerability item has no product_status element"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.7](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61277-vex-product-status).
 */
object Test61277VEXProductStatus : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is VEX) {
            return ValidationNotApplicable
        }

        val missing =
            doc.vulnerabilities?.filter {
                it.product_status?.fixed == null &&
                    it.product_status?.known_affected == null &&
                    it.product_status?.known_not_affected == null &&
                    it.product_status?.under_investigation == null
            } ?: listOf()

        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "None of the elements fixed, known_affected, known_not_affected, or under_investigation is present in product_status"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.8](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61278-vulnerability-id).
 */
object Test61278VulnerabilityID : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is VEX) {
            return ValidationNotApplicable
        }

        val missing = doc.vulnerabilities?.filter { it.cve == null && it.ids == null } ?: listOf()

        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("None of the elements cve or ids is present"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.9](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61279-impact-statement).
 */
object Test61279ImpactStatement : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is VEX) {
            return ValidationNotApplicable
        }

        // First, make a map of all product groups and their product IDs, so we can resolve them
        // later
        val map = doc.gatherProductIdsPerGroup()
        val missing = mutableSetOf<String>()

        for (vuln in doc.vulnerabilities ?: listOf()) {
            val impactStatementsForProductIDs =
                (vuln.threats
                        ?.filter { it.category == Csaf.Category7.impact }
                        ?.flatMap { it.product_ids + it.group_ids.resolveProductIDs(map) } +
                        vuln.flags?.flatMap {
                            it.product_ids + it.group_ids.resolveProductIDs(map)
                        })
                    .toSet()

            missing += vuln.product_status?.known_not_affected - impactStatementsForProductIDs
        }

        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("Missing impact statement for product IDs: ${missing.joinToString(", ")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.10](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#612710-action-statement).
 */
object Test612710ActionStatement : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is VEX) {
            return ValidationNotApplicable
        }

        // First, make a map all product groups and their product IDs, so we can resolve them later
        val map = doc.gatherProductIdsPerGroup()
        val missing = mutableSetOf<String>()

        for (vuln in doc.vulnerabilities ?: listOf()) {
            val actionStatementsForProductIDs =
                vuln.remediations
                    ?.flatMap { it.product_ids + it.group_ids.resolveProductIDs(map) }
                    ?.toSet()

            missing += vuln.product_status?.known_affected - actionStatementsForProductIDs
        }

        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("Missing action statement for product IDs: ${missing.joinToString(", ")}")
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.27.11](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#612711-vulnerabilities).
 */
object Test612711Vulnerabilities : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.profile !is VEX && doc.profile !is SecurityAdvisory) {
            return ValidationNotApplicable
        }

        return if (doc.vulnerabilities != null) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The element /vulnerabilities does not exist"))
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.28](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6128-translation).
 */
object Test6128Translation : Test {
    override fun test(doc: Csaf): ValidationResult {
        val sourceLang = doc.document.source_lang
        val lang = doc.document.lang

        return if (sourceLang != lang || lang == null) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The document language and the source language have the same value: ${doc.document.source_lang}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.29](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6129-remediation-without-product-reference).
 */
object Test6129RemediationWithoutProductReference : Test {
    override fun test(doc: Csaf): ValidationResult {
        val withoutRef =
            doc.vulnerabilities?.flatMap {
                it.remediations?.filter { it.product_ids == null && it.group_ids == null }
                    ?: listOf()
            } ?: listOf()

        return if (withoutRef.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The given remediation does not specify to which products it should be applied"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.30](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6130-mixed-integer-and-semantic-versioning).
 */
object Test6130MixedIntegerAndSemanticVersioning : Test {
    override fun test(doc: Csaf): ValidationResult {
        val versions =
            listOf(
                *doc.document.tracking.revision_history.map { it.number }.toTypedArray(),
                doc.document.tracking.version,
            )

        val isSemver = versions.first().toSemVer() != null
        val invalids =
            if (isSemver) {
                    versions.map { Pair(it, it.toSemVer()) }.filter { it.second == null }
                } else {
                    versions.map { Pair(it, it.toIntOrNull()) }.filter { it.second == null }
                }
                .map { it.first }

        return if (invalids.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The following versions are invalid because of a mix of integer and semantic versioning: ${invalids.joinToString(", ")}"
                )
            )
        }
    }
}

val keywords = listOf("after", "all", "before", "earlier", "later", "prior", "versions")
val operatorsRegex = """(?)(<|<=|>>=|>)""".toRegex()

/**
 * Implementation of
 * [Test 6.1.31](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6131-version-range-in-product-version).
 */
object Test6131VersionRangeInProductVersion : Test {
    override fun test(doc: Csaf): ValidationResult {
        var versions =
            doc.product_tree.mapBranchesNotNull(
                predicate = { it.category == Csaf.Category3.product_version }
            ) {
                it.name
            }
        val invalids =
            versions.filter {
                operatorsRegex.containsMatchIn(it) ||
                    keywords.any { kw -> it.split("""\s""".toRegex()).contains(kw) }
            }
        return if (invalids.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The following product versions are invalid and contain version ranges: ${invalids.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.31](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6132-flag-without-product-reference).
 */
object Test6132FlatWithoutProductReference : Test {
    override fun test(doc: Csaf): ValidationResult {
        val missing =
            doc.vulnerabilities
                ?.flatMap { it.flags ?: setOf() }
                ?.filter { it.group_ids == null && it.product_ids == null } ?: listOf()
        return if (missing.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The following flags are missing products or groups: ${missing.map { it.label }.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.1.33](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6133-multiple-flags-with-vex-justification-codes-per-product).
 */
object Test6133MultipleFlagsWithVEXJustificationCodesPerProduct : Test {
    override fun test(doc: Csaf): ValidationResult {
        var duplicates = mutableListOf<String>()
        var groupMap = doc.gatherProductIdsPerGroup()

        for (vuln in doc.vulnerabilities ?: listOf()) {
            val productsIDsInFlags =
                vuln.flags?.flatMap { it.product_ids + it.group_ids.resolveProductIDs(groupMap) }

            duplicates += productsIDsInFlags.duplicates().keys
        }

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf(
                    "The following product IDs are part of multiple flags: ${duplicates.joinToString(", ")}"
                )
            )
        }
    }
}

/**
 * Implementation of
 * [Test 6.2.1](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#621-unused-definition-of-product-id).
 */
object Test621UnusedDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        if (doc.document.category == "csaf_informational_advisory") {
            return ValidationNotApplicable
        }

        val definitions = doc.gatherProductDefinitions()
        val references = doc.gatherProductReferences()

        val notUsed = definitions.subtract(references.toSet())
        return if (notUsed.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The following IDs are not used: ${notUsed.joinToString(",")}"))
        }
    }
}
