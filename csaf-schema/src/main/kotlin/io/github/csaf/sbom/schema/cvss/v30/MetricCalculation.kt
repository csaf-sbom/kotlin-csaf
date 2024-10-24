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
package io.github.csaf.sbom.schema.cvss.v30

import io.github.csaf.sbom.schema.MetricShortName
import io.github.csaf.sbom.schema.ceil
import io.github.csaf.sbom.schema.cvss.*
import io.github.csaf.sbom.schema.cvss.CVSSMetrics
import io.github.csaf.sbom.schema.generated.CvssV30
import kotlin.math.min
import kotlin.math.pow

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

val valueMapping =
    mapOf(
        // Base
        CvssV30.AttackVector::class to
            mapOf(
                "N" to CvssV30.AttackVector.NETWORK,
                "A" to CvssV30.AttackVector.ADJACENT_NETWORK,
                "L" to CvssV30.AttackVector.LOCAL,
                "P" to CvssV30.AttackVector.PHYSICAL,
            ),
        CvssV30.AttackComplexity::class to
            mapOf(
                "L" to CvssV30.AttackComplexity.LOW,
                "H" to CvssV30.AttackComplexity.HIGH,
            ),
        CvssV30.PrivilegesRequired::class to
            mapOf(
                "N" to CvssV30.PrivilegesRequired.NONE,
                "L" to CvssV30.PrivilegesRequired.LOW,
                "H" to CvssV30.PrivilegesRequired.HIGH,
            ),
        CvssV30.UserInteraction::class to
            mapOf(
                "N" to CvssV30.UserInteraction.NONE,
                "R" to CvssV30.UserInteraction.REQUIRED,
            ),
        CvssV30.Scope::class to
            mapOf(
                "U" to CvssV30.Scope.UNCHANGED,
                "C" to CvssV30.Scope.CHANGED,
            ),
        CvssV30.ConfidentialityImpact::class to
            mapOf(
                "H" to CvssV30.ConfidentialityImpact.HIGH,
                "L" to CvssV30.ConfidentialityImpact.LOW,
                "N" to CvssV30.ConfidentialityImpact.NONE,
            ),

        // Temporal
        CvssV30.ExploitCodeMaturity::class to
            mapOf(
                "X" to CvssV30.ExploitCodeMaturity.NOT_DEFINED,
                "H" to CvssV30.ExploitCodeMaturity.HIGH,
                "F" to CvssV30.ExploitCodeMaturity.FUNCTIONAL,
                "P" to CvssV30.ExploitCodeMaturity.PROOF_OF_CONCEPT,
                "U" to CvssV30.ExploitCodeMaturity.UNPROVEN,
            ),
        CvssV30.RemediationLevel::class to
            mapOf(
                "X" to CvssV30.RemediationLevel.NOT_DEFINED,
                "U" to CvssV30.RemediationLevel.UNAVAILABLE,
                "W" to CvssV30.RemediationLevel.WORKAROUND,
                "T" to CvssV30.RemediationLevel.TEMPORARY_FIX,
                "O" to CvssV30.RemediationLevel.OFFICIAL_FIX,
            ),
        CvssV30.ReportConfidence::class to
            mapOf(
                "X" to CvssV30.ReportConfidence.NOT_DEFINED,
                "C" to CvssV30.ReportConfidence.CONFIRMED,
                "R" to CvssV30.ReportConfidence.REASONABLE,
                "U" to CvssV30.ReportConfidence.UNKNOWN,
            ),

        // Environmental
        CvssV30.ConfidentialityRequirement::class to
            mapOf(
                "X" to CvssV30.ConfidentialityRequirement.NOT_DEFINED,
                "H" to CvssV30.ConfidentialityRequirement.HIGH,
                "M" to CvssV30.ConfidentialityRequirement.MEDIUM,
                "L" to CvssV30.ConfidentialityRequirement.LOW
            ),
        CvssV30.ModifiedAttackVector::class to
            mapOf(
                "X" to CvssV30.ModifiedAttackVector.NOT_DEFINED,
                "N" to CvssV30.ModifiedAttackVector.NETWORK,
                "A" to CvssV30.ModifiedAttackVector.ADJACENT_NETWORK,
                "L" to CvssV30.ModifiedAttackVector.LOCAL,
                "P" to CvssV30.ModifiedAttackVector.PHYSICAL
            ),
        CvssV30.ModifiedAttackComplexity::class to
            mapOf(
                "X" to CvssV30.ModifiedAttackComplexity.NOT_DEFINED,
                "L" to CvssV30.ModifiedAttackComplexity.LOW,
                "H" to CvssV30.ModifiedAttackComplexity.HIGH
            ),
        CvssV30.ModifiedPrivilegesRequired::class to
            mapOf(
                "X" to CvssV30.ModifiedPrivilegesRequired.NOT_DEFINED,
                "N" to CvssV30.ModifiedPrivilegesRequired.NONE,
                "L" to CvssV30.ModifiedPrivilegesRequired.LOW,
                "H" to CvssV30.ModifiedPrivilegesRequired.HIGH,
            ),
        CvssV30.ModifiedUserInteraction::class to
            mapOf(
                "X" to CvssV30.ModifiedUserInteraction.NOT_DEFINED,
                "N" to CvssV30.ModifiedUserInteraction.NONE,
                "R" to CvssV30.ModifiedUserInteraction.REQUIRED,
            ),
        CvssV30.ModifiedScope::class to
            mapOf(
                "X" to CvssV30.ModifiedScope.NOT_DEFINED,
                "U" to CvssV30.ModifiedScope.UNCHANGED,
                "C" to CvssV30.ModifiedScope.CHANGED,
            ),
        CvssV30.ModifiedConfidentialityImpact::class to
            mapOf(
                "X" to CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
                "N" to CvssV30.ModifiedConfidentialityImpact.NONE,
                "L" to CvssV30.ModifiedConfidentialityImpact.LOW,
                "H" to CvssV30.ModifiedConfidentialityImpact.HIGH
            ),
    )

class CVSS30Metrics(
    override val metrics: MutableMap<MetricShortName, String>,
) : CVSSMetrics {
    // Base
    val scope by requiredMetric<CvssV30.Scope>("S")
    val confidentialityImpact by requiredMetric<CvssV30.ConfidentialityImpact>("C")
    val integrityImpact by requiredMetric<CvssV30.ConfidentialityImpact>("I")
    val availabilityImpact by requiredMetric<CvssV30.ConfidentialityImpact>("A")
    val attackVector by requiredMetric<CvssV30.AttackVector>("AV")
    val attackComplexity by requiredMetric<CvssV30.AttackComplexity>("AC")
    val privilegesRequired by requiredMetric<CvssV30.PrivilegesRequired>("PR")
    val userInteraction by requiredMetric<CvssV30.UserInteraction>("UI")

    // Temporal
    val exploitCodeMaturity by optionalMetric<CvssV30.ExploitCodeMaturity>("E")
    val remediationLevel by optionalMetric<CvssV30.RemediationLevel>("RL")
    val reportConfidence by optionalMetric<CvssV30.ReportConfidence>("RC")

    // Environmental (additional properties)
    val confidentialityRequirement by optionalMetric<CvssV30.ConfidentialityRequirement>("CR")
    val integrityRequirement by optionalMetric<CvssV30.ConfidentialityRequirement>("IR")
    val availabilityRequirement by optionalMetric<CvssV30.ConfidentialityRequirement>("AR")

    // Environmental (modified, delegates)
    val modifiedAttackVector by
        modifiedMetric("MAV", CvssV30.ModifiedAttackVector.NOT_DEFINED, CVSS30Metrics::attackVector)
    val modifiedAttackComplexity by
        modifiedMetric(
            "MAC",
            CvssV30.ModifiedAttackComplexity.NOT_DEFINED,
            CVSS30Metrics::attackComplexity
        )
    val modifiedPrivilegesRequired by
        modifiedMetric(
            "MPR",
            CvssV30.ModifiedPrivilegesRequired.NOT_DEFINED,
            CVSS30Metrics::privilegesRequired
        )
    val modifiedUserInteraction by
        modifiedMetric(
            "MUI",
            CvssV30.ModifiedUserInteraction.NOT_DEFINED,
            CVSS30Metrics::userInteraction
        )
    val modifiedScope by
        modifiedMetric("MS", CvssV30.ModifiedScope.NOT_DEFINED, CVSS30Metrics::scope)
    val modifiedConfidentialityImpact by
        modifiedMetric(
            "MC",
            CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
            CVSS30Metrics::confidentialityImpact
        )
    val modifiedIntegrityImpact by
        modifiedMetric(
            "MI",
            CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
            CVSS30Metrics::integrityImpact
        )
    val modifiedAvailabilityImpact by
        modifiedMetric(
            "MA",
            CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
            CVSS30Metrics::availabilityImpact
        )

    override fun calculateBaseScore(): Double {
        val impact = calculateImpact()
        val exploit = calculateExploitability()
        return if (impact <= 0.0) {
            0.0
        } else if (scope.numericalValue == 0.0) {
            ceil(min(impact + exploit, 10.0), digits = 1)
        } else {
            ceil(min(1.08 * (impact + exploit), 10.0), digits = 1)
        }
    }

    companion object {
        fun fromVectorString(vec: String): CVSS30Metrics {
            // Split the vector into parts
            val parts = vec.split("/")

            // First part must be CVSS:3.0
            if (parts.isEmpty() || parts[0] != "CVSS:3.0") {
                throw IllegalArgumentException("Invalid CVSS format or version")
            }

            // A map of metrics and their values.
            val metrics = mutableMapOf<MetricShortName, String>()

            for (part in parts) {
                val (key, value) = part.split(":")

                if (key in metrics) {
                    // Metric was already defined -> illegal
                    throw IllegalArgumentException("metric $key already defined")
                } else {
                    metrics[key] = value
                }
            }

            return CVSS30Metrics(metrics)
        }
    }
}

fun CVSS30Metrics.calculateModifiedImpact(): Double {
    val iscModified =
        min(
            (1 -
                (1 - modifiedConfidentialityImpact * confidentialityRequirement) *
                    (1 - modifiedIntegrityImpact * integrityRequirement) *
                    (1 - modifiedAvailabilityImpact * availabilityRequirement)),
            0.915
        )
    return if (modifiedScope.numericalValue == 0.0) {
        6.42 * iscModified
    } else {
        7.52 * (iscModified - 0.029) - 3.25 * (iscModified - 0.02).pow(15)
    }
}

fun CVSS30Metrics.calculateModifiedExploitability(): Double {
    return 8.22 *
        modifiedAttackVector *
        modifiedAttackComplexity *
        modifiedPrivilegesRequired *
        modifiedUserInteraction
}

fun CVSS30Metrics.calculateTemporalScore(baseScore: Double): Double {
    return ceil(baseScore * exploitCodeMaturity * remediationLevel * reportConfidence, digits = 1)
}

fun CVSS30Metrics.calculateEnvironmentalScore(): Double {
    val impact = calculateModifiedImpact()
    val exploitability = calculateModifiedExploitability()

    return if (impact <= 0.0) {
        0.0
    } else if (modifiedScope.numericalValue == 0.0) {
        ceil(
            ceil(min((impact + exploitability), 10.0), digits = 1) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence,
            digits = 1
        )
    } else {
        ceil(
            ceil(min(1.08 * (impact + exploitability), 10.0), digits = 1) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence,
            digits = 1
        )
    }
}

fun CVSS30Metrics.calculateImpact(): Double {
    val iscBase =
        1.0 - ((1.0 - confidentialityImpact) * (1.0 - integrityImpact) * (1.0 - availabilityImpact))
    return if (scope.numericalValue == 0.0) {
        6.42 * iscBase
    } else {
        7.52 * (iscBase - 0.029) - 3.52 * (iscBase - 0.02).pow(15)
    }
}

fun CVSS30Metrics.calculateExploitability(): Double {
    return 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction
}
