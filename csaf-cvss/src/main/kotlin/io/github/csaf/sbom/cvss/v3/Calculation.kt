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
package io.github.csaf.sbom.cvss.v3

import io.github.csaf.sbom.cvss.CvssCalculation
import io.github.csaf.sbom.cvss.minus
import io.github.csaf.sbom.cvss.optionalMetric
import io.github.csaf.sbom.cvss.requiredMetric
import io.github.csaf.sbom.cvss.times
import io.github.csaf.sbom.cvss.toSeverity
import io.github.csaf.sbom.schema.generated.Csaf.*
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt

class CvssV3Calculation(
    override val metrics: Map<String, String>,
) : CvssCalculation {
    val version: String?
        get() {
            return metrics["CVSS"]
        }

    // Base
    val scope by
        requiredMetric(
            "S",
            mapOf(
                Scope.CHANGED to Pair("C", 1.0),
                Scope.UNCHANGED to Pair("U", 0.0),
            )
        )
    val confidentialityImpact by
        requiredMetric(
            "C",
            mapOf(
                ConfidentialityImpact1.HIGH to Pair("H", 0.56),
                ConfidentialityImpact1.LOW to Pair("L", 0.22),
                ConfidentialityImpact1.NONE to Pair("N", 0.00),
            )
        )
    val integrityImpact by
        requiredMetric(
            "I",
            mapOf(
                ConfidentialityImpact1.HIGH to Pair("H", 0.56),
                ConfidentialityImpact1.LOW to Pair("L", 0.22),
                ConfidentialityImpact1.NONE to Pair("N", 0.00),
            )
        )
    val availabilityImpact by
        requiredMetric(
            "A",
            mapOf(
                ConfidentialityImpact1.HIGH to Pair("H", 0.56),
                ConfidentialityImpact1.LOW to Pair("L", 0.22),
                ConfidentialityImpact1.NONE to Pair("N", 0.00),
            )
        )
    val attackVector by
        requiredMetric(
            "AV",
            mapOf(
                AttackVector.NETWORK to Pair("N", 0.85),
                AttackVector.ADJACENT_NETWORK to Pair("A", 0.62),
                AttackVector.LOCAL to Pair("L", 0.55),
                AttackVector.PHYSICAL to Pair("P", 0.20),
            )
        )
    val attackComplexity by
        requiredMetric<AttackComplexity>(
            "AC",
            mapOf(
                AttackComplexity.LOW to Pair("L", 0.77),
                AttackComplexity.HIGH to Pair("H", 0.44),
            )
        )
    val privilegesRequired by
        requiredMetric<PrivilegesRequired>(
            "PR",
            mapOf(
                PrivilegesRequired.NONE to Pair("N", 0.85),
                PrivilegesRequired.LOW to
                    Pair(
                        "L",
                        if (scope.numericalValue == 1.0) {
                            0.68
                        } else {
                            0.62
                        }
                    ),
                PrivilegesRequired.HIGH to
                    Pair(
                        "H",
                        if (scope.numericalValue == 1.0) {
                            0.50
                        } else {
                            0.27
                        }
                    ),
            )
        )
    val userInteraction by
        requiredMetric<UserInteraction>(
            "UI",
            mapOf(
                UserInteraction.NONE to Pair("N", 0.85),
                UserInteraction.REQUIRED to Pair("R", 0.62),
            )
        )

    // Temporal
    val exploitCodeMaturity by
        optionalMetric(
            "E",
            mapOf(
                ExploitCodeMaturity.NOT_DEFINED to Pair("X", 1.0),
                ExploitCodeMaturity.HIGH to Pair("H", 1.0),
                ExploitCodeMaturity.FUNCTIONAL to Pair("F", 0.97),
                ExploitCodeMaturity.PROOF_OF_CONCEPT to Pair("P", 0.94),
                ExploitCodeMaturity.UNPROVEN to Pair("U", 0.91),
            )
        )
    val remediationLevel by
        optionalMetric<RemediationLevel>(
            "RL",
            mapOf(
                RemediationLevel.NOT_DEFINED to Pair("X", 1.0),
                RemediationLevel.UNAVAILABLE to Pair("U", 1.0),
                RemediationLevel.WORKAROUND to Pair("W", 0.97),
                RemediationLevel.TEMPORARY_FIX to Pair("T", 0.96),
                RemediationLevel.OFFICIAL_FIX to Pair("O", 0.95),
            )
        )
    val reportConfidence by
        optionalMetric(
            "RC",
            mapOf(
                ReportConfidence1.NOT_DEFINED to Pair("X", 1.0),
                ReportConfidence1.CONFIRMED to Pair("C", 1.0),
                ReportConfidence1.REASONABLE to Pair("R", 0.96),
                ReportConfidence1.UNKNOWN to Pair("U", 0.92)
            )
        )

    // Environmental (additional properties)
    val confidentialityRequirement by
        optionalMetric(
            "CR",
            mapOf(
                ConfidentialityRequirement.NOT_DEFINED to Pair("X", 1.0),
                ConfidentialityRequirement.HIGH to Pair("H", 1.5),
                ConfidentialityRequirement.MEDIUM to Pair("M", 1.0),
                ConfidentialityRequirement.LOW to Pair("L", 0.5)
            )
        )
    val integrityRequirement by
        optionalMetric<ConfidentialityRequirement>(
            "IR",
            mapOf(
                ConfidentialityRequirement.NOT_DEFINED to Pair("X", 1.0),
                ConfidentialityRequirement.HIGH to Pair("H", 1.5),
                ConfidentialityRequirement.MEDIUM to Pair("M", 1.0),
                ConfidentialityRequirement.LOW to Pair("L", 0.5)
            )
        )
    val availabilityRequirement by
        optionalMetric<ConfidentialityRequirement>(
            "AR",
            mapOf(
                ConfidentialityRequirement.NOT_DEFINED to Pair("X", 1.0),
                ConfidentialityRequirement.HIGH to Pair("H", 1.5),
                ConfidentialityRequirement.MEDIUM to Pair("M", 1.0),
                ConfidentialityRequirement.LOW to Pair("L", 0.5)
            )
        )

    // Environmental (modified, delegates)
    val modifiedScope by
        optionalMetric(
            "MS",
            mapOf(
                ModifiedScope.NOT_DEFINED to Pair("X", scope.numericalValue),
                ModifiedScope.CHANGED to Pair("C", 1.0),
                ModifiedScope.UNCHANGED to Pair("U", 0.0),
            )
        )
    val modifiedAttackVector by
        optionalMetric(
            "MAV",
            mapOf(
                ModifiedAttackVector.NOT_DEFINED to Pair("X", attackVector.numericalValue),
                ModifiedAttackVector.NETWORK to Pair("N", 0.85),
                ModifiedAttackVector.ADJACENT_NETWORK to Pair("A", 0.62),
                ModifiedAttackVector.LOCAL to Pair("L", 0.55),
                ModifiedAttackVector.PHYSICAL to Pair("P", 0.20),
            )
        )
    val modifiedAttackComplexity by
        optionalMetric(
            "MAC",
            mapOf(
                ModifiedAttackComplexity.NOT_DEFINED to Pair("X", attackComplexity.numericalValue),
                ModifiedAttackComplexity.LOW to Pair("L", 0.77),
                ModifiedAttackComplexity.HIGH to Pair("H", 0.44),
            )
        )
    val modifiedPrivilegesRequired by
        optionalMetric(
            "MPR",
            mapOf(
                ModifiedPrivilegesRequired.NOT_DEFINED to
                    Pair("X", privilegesRequired.numericalValue),
                ModifiedPrivilegesRequired.NONE to Pair("N", 0.85),
                ModifiedPrivilegesRequired.LOW to
                    Pair(
                        "L",
                        if (modifiedScope.numericalValue == 1.0) {
                            0.68
                        } else {
                            0.62
                        }
                    ),
                ModifiedPrivilegesRequired.HIGH to
                    Pair(
                        "H",
                        if (modifiedScope.numericalValue == 1.0) {
                            0.50
                        } else {
                            0.27
                        }
                    ),
            )
        )
    val modifiedUserInteraction by
        optionalMetric(
            "MUI",
            mapOf(
                ModifiedUserInteraction.NOT_DEFINED to Pair("X", userInteraction.numericalValue),
                ModifiedUserInteraction.NONE to Pair("N", 0.85),
                ModifiedUserInteraction.REQUIRED to Pair("R", 0.62),
            )
        )
    val modifiedConfidentialityImpact by
        optionalMetric(
            "MC",
            mapOf(
                ModifiedConfidentialityImpact.NOT_DEFINED to
                    Pair("X", confidentialityImpact.numericalValue),
                ModifiedConfidentialityImpact.HIGH to Pair("H", 0.56),
                ModifiedConfidentialityImpact.LOW to Pair("L", 0.22),
                ModifiedConfidentialityImpact.NONE to Pair("N", 0.00),
            )
        )
    val modifiedIntegrityImpact by
        optionalMetric(
            "MI",
            mapOf(
                ModifiedConfidentialityImpact.NOT_DEFINED to
                    Pair("X", integrityImpact.numericalValue),
                ModifiedConfidentialityImpact.HIGH to Pair("H", 0.56),
                ModifiedConfidentialityImpact.LOW to Pair("L", 0.22),
                ModifiedConfidentialityImpact.NONE to Pair("N", 0.00),
            )
        )
    val modifiedAvailabilityImpact by
        optionalMetric(
            "MA",
            mapOf(
                ModifiedConfidentialityImpact.NOT_DEFINED to
                    Pair("X", availabilityImpact.numericalValue),
                ModifiedConfidentialityImpact.HIGH to Pair("H", 0.56),
                ModifiedConfidentialityImpact.LOW to Pair("L", 0.22),
                ModifiedConfidentialityImpact.NONE to Pair("N", 0.00),
            )
        )

    // Calculated scores
    val baseScore by lazy { calculateBaseScore() }
    val baseSeverity = baseScore.toSeverity()
    val temporalScore by lazy { calculateTemporalScore() }
    val temporalSeverity = temporalScore.toSeverity()
    val environmentalScore by lazy { calculateEnvironmentalScore() }
    val environmentalSeverity = environmentalScore.toSeverity()

    override fun calculateBaseScore(): Double {
        val impact = calculateImpact()
        val exploit = calculateExploitability()
        return if (impact <= 0.0) {
            0.0
        } else if (scope.numericalValue == 0.0) {
            roundUp(min(impact + exploit, 10.0))
        } else {
            roundUp(min(1.08 * (impact + exploit), 10.0))
        }
    }

    companion object {
        fun fromVectorString(vec: String): CvssV3Calculation {
            // Split the vector into parts
            val parts = vec.split("/")

            // A map of metrics and their values.
            val metrics = mutableMapOf<String, String>()

            for ((idx, part) in parts.withIndex()) {
                val keyValue = part.split(":")
                val key = keyValue.first()
                val value = keyValue.getOrNull(1)

                if (idx == 0 && (key != "CVSS" || (value != "3.0" && value != "3.1"))) {
                    // First key must be CVSS:3.X
                    throw IllegalArgumentException("Invalid CVSS format or version")
                }

                if (value == null) {
                    throw IllegalArgumentException("Value for $key is missing")
                }

                if (key in metrics) {
                    // Metric was already defined -> illegal
                    throw IllegalArgumentException("Metric $key already defined")
                } else {
                    metrics[key] = value
                }
            }

            return CvssV3Calculation(metrics)
        }
    }
}

fun CvssV3Calculation.calculateModifiedImpact(): Double {
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
    } else if (version == "3.1") {
        7.52 * (iscModified - 0.029) - 3.25 * (iscModified * 0.9731 - 0.02).pow(13)
    } else {
        7.52 * (iscModified - 0.029) - 3.25 * (iscModified - 0.02).pow(15)
    }
}

fun CvssV3Calculation.calculateModifiedExploitability(): Double {
    return 8.22 *
        modifiedAttackVector *
        modifiedAttackComplexity *
        modifiedPrivilegesRequired *
        modifiedUserInteraction
}

fun CvssV3Calculation.calculateTemporalScore(): Double {
    return roundUp(calculateBaseScore() * exploitCodeMaturity * remediationLevel * reportConfidence)
}

fun CvssV3Calculation.calculateEnvironmentalScore(): Double {
    val impact = calculateModifiedImpact()
    val exploitability = calculateModifiedExploitability()

    return if (impact <= 0.0) {
        0.0
    } else if (modifiedScope.numericalValue == 0.0) {
        roundUp(
            roundUp(min((impact + exploitability), 10.0)) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence
        )
    } else {
        roundUp(
            roundUp(min(1.08 * (impact + exploitability), 10.0)) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence
        )
    }
}

fun CvssV3Calculation.calculateImpact(): Double {
    val iscBase =
        1.0 - ((1.0 - confidentialityImpact) * (1.0 - integrityImpact) * (1.0 - availabilityImpact))
    return if (scope.numericalValue == 0.0) {
        6.42 * iscBase
    } else {
        7.52 * (iscBase - 0.029) - 3.52 * (iscBase - 0.02).pow(15)
    }
}

fun CvssV3Calculation.calculateExploitability(): Double {
    return 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction
}

/**
 * Implementation of the "round up" function used in the calculations. According to the
 * specification, it should return "the smallest number, specified to 1 decimal place, that is equal
 * to or higher than its input."
 *
 * For CVSS 3.1, it follows the implementation guidance in
 * [Appendix A](https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding).
 */
fun CvssV3Calculation.roundUp(x: Double): Double {
    return if (version == "3.1") {
        var intInput = (x * 100000).roundToInt()
        if ((intInput % 10000) == 0) {
            intInput / 100000.0
        } else {
            return (floor(intInput / 10000.0) + 1) / 10.0
        }
    } else {
        val factor = 10.0.pow(1)
        ceil(x * factor) / factor
    }
}
