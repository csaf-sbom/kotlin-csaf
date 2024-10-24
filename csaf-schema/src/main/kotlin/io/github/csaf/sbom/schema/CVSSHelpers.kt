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
package io.github.csaf.sbom.schema

import io.github.csaf.sbom.schema.cvss.*
import io.github.csaf.sbom.schema.cvss.v30.CVSS30Metrics
import io.github.csaf.sbom.schema.cvss.v30.calculateEnvironmentalScore
import io.github.csaf.sbom.schema.cvss.v30.calculateTemporalScore
import io.github.csaf.sbom.schema.generated.CvssV30
import kotlin.math.ceil
import kotlin.math.pow

typealias MetricShortName = String

fun CvssV30.Companion.fromVectorString(vec: String): CvssV30? {
    // First, gather all the metrics
    val metrics = CVSS30Metrics.fromVectorString(vec)

    val base = metrics.calculateBaseScore()
    val temporalScore = metrics.calculateTemporalScore(baseScore = base)
    val environmentalScore = metrics.calculateEnvironmentalScore()

    val score =
        CvssV30(
            version = "3.0",
            vectorString = vec,
            baseScore = base,
            baseSeverity = base.toSeverity(),
            temporalScore = temporalScore,
            temporalSeverity = temporalScore.toSeverity(),
            environmentalScore = environmentalScore,
            environmentalSeverity = environmentalScore.toSeverity(),
            scope = metrics.scope.enumValue,
            availabilityImpact = metrics.availabilityImpact.enumValue,
            confidentialityImpact = metrics.confidentialityImpact.enumValue,
            integrityImpact = metrics.integrityImpact.enumValue,
            attackVector = metrics.attackVector.enumValue,
            attackComplexity = metrics.attackComplexity.enumValue,
            privilegesRequired = metrics.privilegesRequired.enumValue,
            userInteraction = metrics.userInteraction.enumValue,
            modifiedAttackVector = metrics.modifiedAttackVector.enumValue,
        )

    return score
}

fun <T : Enum<*>> metricLevel(x: T): Map<Enum<*>, Double> {
    return when (x) {
        is CvssV30.AttackVector ->
            return mapOf(
                CvssV30.AttackVector.NETWORK to 0.85,
                CvssV30.AttackVector.ADJACENT_NETWORK to 0.62,
                CvssV30.AttackVector.LOCAL to 0.55,
                CvssV30.AttackVector.PHYSICAL to 0.2
            )
        is CvssV30.ModifiedAttackVector ->
            return mapOf(
                CvssV30.ModifiedAttackVector.NETWORK to 0.85,
                CvssV30.ModifiedAttackVector.ADJACENT_NETWORK to 0.62,
                CvssV30.ModifiedAttackVector.LOCAL to 0.55,
                CvssV30.ModifiedAttackVector.PHYSICAL to 0.2
            )
        is CvssV30.AttackComplexity ->
            mapOf(
                CvssV30.AttackComplexity.LOW to 0.77,
                CvssV30.AttackComplexity.HIGH to 0.44,
            )
        is CvssV30.ModifiedAttackComplexity ->
            mapOf(
                CvssV30.ModifiedAttackComplexity.LOW to 0.77,
                CvssV30.ModifiedAttackComplexity.HIGH to 0.44,
            )
        is CvssV30.PrivilegesRequired ->
            mapOf(
                CvssV30.PrivilegesRequired.NONE to 0.85,
                CvssV30.PrivilegesRequired.LOW to 0.62,
                CvssV30.PrivilegesRequired.HIGH to 0.27,
            )
        is CvssV30.ModifiedPrivilegesRequired ->
            mapOf(
                CvssV30.ModifiedPrivilegesRequired.NONE to 0.85,
                CvssV30.ModifiedPrivilegesRequired.LOW to 0.62,
                CvssV30.ModifiedPrivilegesRequired.HIGH to 0.27,
            )
        is CvssV30.UserInteraction ->
            mapOf(
                CvssV30.UserInteraction.NONE to 0.85,
                CvssV30.UserInteraction.REQUIRED to 0.62,
            )
        is CvssV30.ModifiedUserInteraction ->
            mapOf(
                CvssV30.ModifiedUserInteraction.NONE to 0.85,
                CvssV30.ModifiedUserInteraction.REQUIRED to 0.62,
            )
        is CvssV30.ConfidentialityImpact ->
            mapOf(
                CvssV30.ConfidentialityImpact.HIGH to 0.56,
                CvssV30.ConfidentialityImpact.LOW to 0.22,
                CvssV30.ConfidentialityImpact.NONE to 0.0,
            )
        is CvssV30.ModifiedConfidentialityImpact ->
            mapOf(
                CvssV30.ModifiedConfidentialityImpact.HIGH to 0.56,
                CvssV30.ModifiedConfidentialityImpact.LOW to 0.22,
                CvssV30.ModifiedConfidentialityImpact.NONE to 0.0,
            )
        is CvssV30.ExploitCodeMaturity ->
            mapOf(
                CvssV30.ExploitCodeMaturity.NOT_DEFINED to 1.0,
                CvssV30.ExploitCodeMaturity.HIGH to 1.0,
                CvssV30.ExploitCodeMaturity.FUNCTIONAL to 0.97,
                CvssV30.ExploitCodeMaturity.PROOF_OF_CONCEPT to 0.94,
                CvssV30.ExploitCodeMaturity.UNPROVEN to 0.91,
            )
        is CvssV30.RemediationLevel ->
            mapOf(
                CvssV30.RemediationLevel.NOT_DEFINED to 1.0,
                CvssV30.RemediationLevel.UNAVAILABLE to 1.0,
                CvssV30.RemediationLevel.WORKAROUND to 0.97,
                CvssV30.RemediationLevel.TEMPORARY_FIX to 0.96,
                CvssV30.RemediationLevel.OFFICIAL_FIX to 0.95,
            )
        is CvssV30.ReportConfidence ->
            mapOf(
                CvssV30.ReportConfidence.NOT_DEFINED to 1.0,
                CvssV30.ReportConfidence.CONFIRMED to 1.0,
                CvssV30.ReportConfidence.REASONABLE to 0.96,
                CvssV30.ReportConfidence.UNKNOWN to 0.92,
            )
        is CvssV30.ConfidentialityRequirement ->
            mapOf(
                CvssV30.ConfidentialityRequirement.NOT_DEFINED to 1.0,
                CvssV30.ConfidentialityRequirement.HIGH to 1.5,
                CvssV30.ConfidentialityRequirement.MEDIUM to 1.0,
                CvssV30.ConfidentialityRequirement.LOW to 0.5,
            )
        // This mapping is not in the standard, but we use it so that we can use our delegate system
        is CvssV30.Scope ->
            mapOf(
                CvssV30.Scope.UNCHANGED to 0.0,
                CvssV30.Scope.CHANGED to 1.0,
            )
        is CvssV30.ModifiedScope ->
            mapOf(
                CvssV30.ModifiedScope.UNCHANGED to 0.0,
                CvssV30.ModifiedScope.CHANGED to 1.0,
            )
        else -> throw IllegalArgumentException("invalid enum class: ${x::class.simpleName}")
    }
}

fun <T : Enum<*>> T.numericalValue(): Double {
    val mapping = metricLevel(this)
    return mapping[this]
        ?: throw IllegalArgumentException("unknown value: $this of ${this::class.simpleName}")
}

fun ceil(x: Double, digits: Int): Double {
    val factor = 10.0.pow(digits)
    return ceil(x * factor) / factor
}
