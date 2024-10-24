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
import io.github.csaf.sbom.schema.cvss.modifiedMetric
import io.github.csaf.sbom.schema.generated.CvssV30
import io.github.csaf.sbom.schema.generated.CvssV30.Scope
import io.github.csaf.sbom.schema.numericalValue
import io.github.csaf.sbom.schema.valueOf
import kotlin.math.min
import kotlin.math.pow
import kotlin.reflect.KProperty1

val shortNames =
    mapOf<KProperty1<CvssV30, Any?>, String>(
        // Base
        CvssV30::attackVector to "AV",
        CvssV30::attackComplexity to "AC",
        CvssV30::privilegesRequired to "PR",
        CvssV30::userInteraction to "UI",
        CvssV30::scope to "S",
        CvssV30::confidentialityImpact to "C",
        CvssV30::integrityImpact to "I",
        CvssV30::availabilityImpact to "A",

        // Temporal
        CvssV30::exploitCodeMaturity to "E",
        CvssV30::remediationLevel to "RL",
        CvssV30::reportConfidence to "RC",

        // Environmental
        CvssV30::confidentialityRequirement to "CR",
        CvssV30::integrityRequirement to "IR",
        CvssV30::availabilityRequirement to "AR",
        CvssV30::modifiedAttackVector to "MAV",
        CvssV30::modifiedAttackComplexity to "MAC",
        CvssV30::modifiedPrivilegesRequired to "MPR",
        CvssV30::modifiedUserInteraction to "MUI",
        CvssV30::modifiedScope to "MS",
        CvssV30::modifiedConfidentialityImpact to "MC",
        CvssV30::modifiedIntegrityImpact to "MI",
        CvssV30::modifiedAvailabilityImpact to "MA",
    )

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
    // Base
    val scope: CvssV30.Scope,
    // val confidentialityImpact: CvssV30.ConfidentialityImpact,
    val integrityImpact: CvssV30.ConfidentialityImpact,
    val availabilityImpact: CvssV30.ConfidentialityImpact,
    val attackVector: CvssV30.AttackVector,
    val attackComplexity: CvssV30.AttackComplexity,
    val privilegesRequired: CvssV30.PrivilegesRequired,
    val userInteraction: CvssV30.UserInteraction,

    // Temporal
    val exploitCodeMaturity: CvssV30.ExploitCodeMaturity = CvssV30.ExploitCodeMaturity.NOT_DEFINED,
    val remediationLevel: CvssV30.RemediationLevel = CvssV30.RemediationLevel.NOT_DEFINED,
    val reportConfidence: CvssV30.ReportConfidence = CvssV30.ReportConfidence.NOT_DEFINED,

    // Environmental (additional properties)
    val confidentialityRequirement: CvssV30.ConfidentialityRequirement =
        CvssV30.ConfidentialityRequirement.NOT_DEFINED,
    val integrityRequirement: CvssV30.ConfidentialityRequirement =
        CvssV30.ConfidentialityRequirement.NOT_DEFINED,
    val availabilityRequirement: CvssV30.ConfidentialityRequirement =
        CvssV30.ConfidentialityRequirement.NOT_DEFINED,

    // Environmental (modified, delegated properties)
    modifiedAttackVector: CvssV30.ModifiedAttackVector = CvssV30.ModifiedAttackVector.NOT_DEFINED,
    modifiedAttackComplexity: CvssV30.ModifiedAttackComplexity =
        CvssV30.ModifiedAttackComplexity.NOT_DEFINED,
    modifiedPrivilegesRequired: CvssV30.ModifiedPrivilegesRequired =
        CvssV30.ModifiedPrivilegesRequired.NOT_DEFINED,
    modifiedUserInteraction: CvssV30.ModifiedUserInteraction =
        CvssV30.ModifiedUserInteraction.NOT_DEFINED,
    modifiedScope: CvssV30.ModifiedScope = CvssV30.ModifiedScope.NOT_DEFINED,
    modifiedConfidentialityImpact: CvssV30.ModifiedConfidentialityImpact =
        CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
    modifiedIntegrityImpact: CvssV30.ModifiedConfidentialityImpact =
        CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
    modifiedAvailabilityImpact: CvssV30.ModifiedConfidentialityImpact =
        CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
) : CVSSMetrics {

    val scope2 by metric("S", CvssV30.Scope::class)
    val confidentialityImpact by metric("C", CvssV30.ConfidentialityImpact::class)

    val modifiedAttackVector by
        modifiedMetric(
            modifiedAttackVector,
            CvssV30.ModifiedAttackVector.NOT_DEFINED,
            CVSS30Metrics::attackVector
        )

    val modifiedAttackComplexity by
        modifiedMetric(
            modifiedAttackComplexity,
            CvssV30.ModifiedAttackComplexity.NOT_DEFINED,
            CVSS30Metrics::attackComplexity
        )

    val modifiedPrivilegesRequired by
        modifiedMetric(
            modifiedPrivilegesRequired,
            CvssV30.ModifiedPrivilegesRequired.NOT_DEFINED,
            CVSS30Metrics::privilegesRequired
        )

    val modifiedUserInteraction by
        modifiedMetric(
            modifiedUserInteraction,
            CvssV30.ModifiedUserInteraction.NOT_DEFINED,
            CVSS30Metrics::userInteraction
        )

    val modifiedScope by
        modifiedMetric(modifiedScope, CvssV30.ModifiedScope.NOT_DEFINED, CVSS30Metrics::scope)

    val modifiedConfidentialityImpact by
        modifiedMetric(
            modifiedConfidentialityImpact,
            CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
            CVSS30Metrics::confidentialityImpact
        )

    val modifiedIntegrityImpact by
        modifiedMetric(
            modifiedIntegrityImpact,
            CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
            CVSS30Metrics::integrityImpact
        )

    val modifiedAvailabilityImpact by
        modifiedMetric(
            modifiedAvailabilityImpact,
            CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
            CVSS30Metrics::availabilityImpact
        )

    override fun calculateBaseScore(): Double {
        val impact = calculateImpact()
        val exploit = calculateExploitability()
        return if (impact <= 0.0) {
            0.0
        } else if (scope == Scope.UNCHANGED) {
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

            return CVSS30Metrics(
                metrics,
                // Base
                scope = metrics.valueOf(CvssV30::scope),
                // confidentialityImpact = metrics.valueOf(CvssV30::confidentialityImpact),
                integrityImpact = metrics.valueOf(CvssV30::integrityImpact),
                availabilityImpact = metrics.valueOf(CvssV30::availabilityImpact),
                attackVector = metrics.valueOf(CvssV30::attackVector),
                attackComplexity = metrics.valueOf(CvssV30::attackComplexity),
                privilegesRequired = metrics.valueOf(CvssV30::privilegesRequired),
                userInteraction = metrics.valueOf(CvssV30::userInteraction),

                // Temporal
                exploitCodeMaturity =
                    metrics.valueOf(CvssV30::exploitCodeMaturity, required = false),
                remediationLevel = metrics.valueOf(CvssV30::remediationLevel, required = false),
                reportConfidence = metrics.valueOf(CvssV30::reportConfidence, required = false),

                // Environmental
                confidentialityRequirement =
                    metrics.valueOf(CvssV30::confidentialityRequirement, required = false),
                integrityRequirement =
                    metrics.valueOf(CvssV30::integrityRequirement, required = false),
                availabilityRequirement =
                    metrics.valueOf(CvssV30::availabilityRequirement, required = false),
                modifiedAttackVector =
                    metrics.valueOf(CvssV30::modifiedAttackVector, required = false),
                modifiedAttackComplexity =
                    metrics.valueOf(CvssV30::modifiedAttackComplexity, required = false),
                modifiedPrivilegesRequired =
                    metrics.valueOf(CvssV30::modifiedPrivilegesRequired, required = false),
                modifiedUserInteraction =
                    metrics.valueOf(CvssV30::modifiedUserInteraction, required = false),
                modifiedScope = metrics.valueOf(CvssV30::modifiedScope, required = false),
                modifiedConfidentialityImpact =
                    metrics.valueOf(CvssV30::modifiedConfidentialityImpact, required = false),
                modifiedIntegrityImpact =
                    metrics.valueOf(CvssV30::modifiedIntegrityImpact, required = false),
                modifiedAvailabilityImpact =
                    metrics.valueOf(CvssV30::modifiedAvailabilityImpact, required = false),
            )
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
    return if (modifiedScope == CvssV30.ModifiedScope.UNCHANGED) {
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
    return ceil(
        baseScore *
            exploitCodeMaturity.numericalValue() *
            remediationLevel.numericalValue() *
            reportConfidence.numericalValue(),
        digits = 1
    )
}

fun CVSS30Metrics.calculateEnvironmentalScore(): Double {
    val impact = calculateModifiedImpact()
    val exploitability = calculateModifiedExploitability()
    val scope =
        if (modifiedScope != CvssV30.ModifiedScope.NOT_DEFINED) {
            modifiedScope
        } else {
            scope
        }

    return if (impact <= 0.0) {
        0.0
    } else if (scope == CvssV30.ModifiedScope.UNCHANGED) {
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
    return if (scope == CvssV30.Scope.UNCHANGED) {
        6.42 * iscBase
    } else {
        7.52 * (iscBase - 0.029) - 3.52 * (iscBase - 0.02).pow(15)
    }
}

fun CVSS30Metrics.calculateExploitability(): Double {
    return 8.22 *
        attackVector.numericalValue() *
        attackComplexity.numericalValue() *
        privilegesRequired.numericalValue() *
        userInteraction.numericalValue()
}
