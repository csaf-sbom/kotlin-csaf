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

import io.github.csaf.sbom.cvss.MetricValue
import io.github.csaf.sbom.cvss.v3.CvssV3Calculation
import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.Test
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationResult
import io.github.csaf.sbom.validation.ValidationSuccessful
import io.github.csaf.sbom.validation.merge
import kotlin.reflect.KProperty1
import net.swiftzer.semver.SemVer

/**
 * Mandatory tests as defined in
 * [Section 6.1](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#61-mandatory-tests).
 */
var mandatoryTests =
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
        Test6114SortedRevisionHistory,
        Test6116LatestDocumentVersion,
        Test6117DocumentStatusDraft,
        Test6118ReleasedRevisionHistory,
        Test6119RevisionHistoryEntriesForPreReleaseVersions,
        Test6120NonDraftDocumentVersion,
        Test6121MissingItemInRevisionHistory,
        Test6122MultipleDefinitionInRevisionHistory
    )

/**
 * Optional tests as defined in
 * [Section 6.2](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#62-optional-tests).
 */
var optionalTests =
    listOf(
        Test621UnusedDefinitionOfProductID,
    )

/**
 * Informative tests as defined in
 * [Section 6.3](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#63-informative-test).
 */
var informativeTests = listOf<Test>()

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

private fun <T> List<T>.duplicates(): Map<T, Int> {
    return groupingBy { it }.eachCount().filter { it.value > 1 }
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
 * [Test 6.1.14](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6114-sorted-revision-history).
 */
object Test6114SortedRevisionHistory : Test {
    override fun test(doc: Csaf): ValidationResult {
        // First, sort items ascending by number
        val sortedByNumber =
            doc.document.tracking.revision_history.sortedWith { h1, h2 ->
                h1.number.compareVersionTo(h2.number)
            }

        // Then, check if it is sorted by date
        val isSorted =
            sortedByNumber.asSequence().zipWithNext { a, b -> a.date <= b.date }.all { it }
        return if (isSorted) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The revision history is not sorted by ascending date"))
        }
        println(isSorted)
    }
}

/**
 * Implementation of
 * [Test 6.1.16](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6116-latest-document-version).
 */
object Test6116LatestDocumentVersion : Test {
    override fun test(doc: Csaf): ValidationResult {
        // First, sort items ascending by number
        val sortedByNumber =
            doc.document.tracking.revision_history.sortedWith { h1, h2 ->
                h1.number.compareVersionTo(h2.number)
            }
        val latestVersion = sortedByNumber.last().number

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
            var next = prev.number.versionOrMajorVersion + 1
            if (
                next != current.number.versionOrMajorVersion &&
                    prev.number.versionOrMajorVersion != current.number.versionOrMajorVersion
            ) {
                missing += next.toString()
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
 * [Test 6.2.1](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#621-unused-definition-of-product-id).
 */
object Test621UnusedDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
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
