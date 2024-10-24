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
import io.github.csaf.sbom.schema.calculateExploitability
import io.github.csaf.sbom.schema.calculateImpact
import io.github.csaf.sbom.schema.ceil
import io.github.csaf.sbom.schema.cvss.common.CVSSMetrics
import io.github.csaf.sbom.schema.cvss.common.modifiedMetric
import io.github.csaf.sbom.schema.generated.CvssV30
import io.github.csaf.sbom.schema.generated.CvssV30.Scope
import io.github.csaf.sbom.schema.numericalValue
import io.github.csaf.sbom.schema.times
import io.github.csaf.sbom.schema.valueOf
import kotlin.math.min
import kotlin.math.pow

class CVSS30Metrics(
    // Base
    val scope: CvssV30.Scope,
    val confidentialityImpact: CvssV30.ConfidentialityImpact,
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
        val impact =
            calculateImpact(scope, confidentialityImpact, integrityImpact, availabilityImpact)
        val exploit =
            calculateExploitability(
                attackVector,
                attackComplexity,
                privilegesRequired,
                userInteraction
            )
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
                // Base
                scope = metrics.valueOf(CvssV30::scope),
                confidentialityImpact = metrics.valueOf(CvssV30::confidentialityImpact),
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
