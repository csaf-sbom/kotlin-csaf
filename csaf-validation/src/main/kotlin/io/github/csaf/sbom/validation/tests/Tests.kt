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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

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
        Test6110InconsistentCVSS
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

val test619PropertiesMap =
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
                for (entry in test619PropertiesMap) {
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

val JsonObject?.version: String?
    get() {
        val primitive = this?.get("version") as? JsonPrimitive
        return if (primitive?.isString == true) {
            primitive.content
        } else {
            null
        }
    }
