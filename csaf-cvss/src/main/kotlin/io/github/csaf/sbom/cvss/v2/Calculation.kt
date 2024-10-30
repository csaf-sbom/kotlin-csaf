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
package io.github.csaf.sbom.cvss.v2

import io.github.csaf.sbom.cvss.*
import io.github.csaf.sbom.schema.generated.Csaf.*
import kotlin.math.min
import kotlin.math.round

class CvssV2Calculation(override val metrics: Map<String, String>) : CvssCalculation {
    // Base
    val accessVector by
        requiredMetric(
            "AV",
            mapOf(
                AccessVector.LOCAL to Pair("L", 0.395),
                AccessVector.ADJACENT_NETWORK to Pair("A", 0.646),
                AccessVector.NETWORK to Pair("N", 1.0),
            )
        )
    val accessComplexity by
        requiredMetric(
            "AC",
            mapOf(
                AccessComplexity.HIGH to Pair("H", 0.35),
                AccessComplexity.MEDIUM to Pair("M", 0.61),
                AccessComplexity.LOW to Pair("L", 0.71),
            )
        )
    val authentication by
        requiredMetric(
            "Au",
            mapOf(
                Authentication.MULTIPLE to Pair("M", 0.45),
                Authentication.SINGLE to Pair("S", 0.56),
                Authentication.NONE to Pair("N", 0.704),
            )
        )
    val confidentialityImpact by
        requiredMetric(
            "C",
            mapOf(
                ConfidentialityImpact.NONE to Pair("N", 0.0),
                ConfidentialityImpact.PARTIAL to Pair("P", 0.275),
                ConfidentialityImpact.COMPLETE to Pair("C", 0.660),
            )
        )
    val integrityImpact by
        requiredMetric(
            "I",
            mapOf(
                ConfidentialityImpact.NONE to Pair("N", 0.0),
                ConfidentialityImpact.PARTIAL to Pair("P", 0.275),
                ConfidentialityImpact.COMPLETE to Pair("C", 0.660),
            )
        )
    val availabilityImpact by
        requiredMetric(
            "A",
            mapOf(
                ConfidentialityImpact.NONE to Pair("N", 0.0),
                ConfidentialityImpact.PARTIAL to Pair("P", 0.275),
                ConfidentialityImpact.COMPLETE to Pair("C", 0.660),
            )
        )

    // Temporal
    val exploitability by
        optionalMetric(
            "E",
            mapOf(
                Exploitability.UNPROVEN to Pair("U", 0.85),
                Exploitability.PROOF_OF_CONCEPT to Pair("POC", 0.9),
                Exploitability.FUNCTIONAL to Pair("F", 0.95),
                Exploitability.HIGH to Pair("H", 1.0),
                Exploitability.NOT_DEFINED to Pair("ND", 1.0),
            )
        )
    val remediationLevel by
        optionalMetric(
            "RL",
            mapOf(
                RemediationLevel.OFFICIAL_FIX to Pair("OF", 0.87),
                RemediationLevel.TEMPORARY_FIX to Pair("TF", 0.90),
                RemediationLevel.WORKAROUND to Pair("W", 0.95),
                RemediationLevel.UNAVAILABLE to Pair("U", 1.0),
                RemediationLevel.NOT_DEFINED to Pair("ND", 1.0)
            )
        )
    val reportConfidence by
        optionalMetric(
            "RC",
            mapOf(
                ReportConfidence.UNCONFIRMED to Pair("UC", 0.90),
                ReportConfidence.UNCORROBORATED to Pair("UR", 0.95),
                ReportConfidence.CONFIRMED to Pair("C", 1.0),
                ReportConfidence.NOT_DEFINED to Pair("ND", 1.0)
            )
        )

    // Environmental
    val collateralDamagePotential by
        optionalMetric(
            "CDP",
            mapOf(
                CollateralDamagePotential.NONE to Pair("N", 0.0),
                CollateralDamagePotential.LOW to Pair("L", 0.1),
                CollateralDamagePotential.LOW_MEDIUM to Pair("LM", 0.3),
                CollateralDamagePotential.MEDIUM_HIGH to Pair("MH", 0.4),
                CollateralDamagePotential.HIGH to Pair("H", 0.5),
                CollateralDamagePotential.NOT_DEFINED to Pair("ND", 0.0),
            )
        )
    val targetDistribution by
        optionalMetric(
            "TD",
            mapOf(
                TargetDistribution.NONE to Pair("N", 0.0),
                TargetDistribution.LOW to Pair("L", 0.25),
                TargetDistribution.MEDIUM to Pair("M", 0.75),
                TargetDistribution.HIGH to Pair("H", 1.0),
                TargetDistribution.NOT_DEFINED to Pair("ND", 1.0),
            )
        )
    val confidentialityRequirement by
        optionalMetric(
            "CR",
            mapOf(
                ConfidentialityRequirement.LOW to Pair("L", 0.5),
                ConfidentialityRequirement.MEDIUM to Pair("M", 1.0),
                ConfidentialityRequirement.HIGH to Pair("H", 1.51),
                ConfidentialityRequirement.NOT_DEFINED to Pair("ND", 1.0),
            )
        )
    val integrityRequirement by
        optionalMetric(
            "CR",
            mapOf(
                ConfidentialityRequirement.LOW to Pair("L", 0.5),
                ConfidentialityRequirement.MEDIUM to Pair("M", 1.0),
                ConfidentialityRequirement.HIGH to Pair("H", 1.51),
                ConfidentialityRequirement.NOT_DEFINED to Pair("ND", 1.0),
            )
        )
    val availabilityRequirement by
        optionalMetric(
            "CR",
            mapOf(
                ConfidentialityRequirement.LOW to Pair("L", 0.5),
                ConfidentialityRequirement.MEDIUM to Pair("M", 1.0),
                ConfidentialityRequirement.HIGH to Pair("H", 1.51),
                ConfidentialityRequirement.NOT_DEFINED to Pair("ND", 1.0),
            )
        )

    // Calculated scores
    val baseScore = calculateBaseScore()
    val baseSeverity
        get() = baseScore.toSeverity()

    val temporalScore by lazy { calculateTemporalScore() }
    val temporalSeverity
        get() = temporalScore.toSeverity()

    val environmentalScore by lazy { calculateEnvironmentalScore() }
    val environmentalSeverity
        get() = environmentalScore.toSeverity()

    override fun calculateBaseScore(): Double {
        val impact =
            10.41 *
                (1 -
                    (1.0 - confidentialityImpact) *
                        (1.0 - integrityImpact) *
                        (1.0 - availabilityImpact))
        return baseScoreForImpact(impact)
    }

    private fun baseScoreForImpact(impact: Double): Double {
        val exploitability = 20.0 * accessVector * accessComplexity * authentication
        val fImpact =
            if (impact == 0.0) {
                0.0
            } else {
                1.176
            }
        return roundTo1Decimal(((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact)
    }

    override fun calculateTemporalScore(): Double {
        return roundTo1Decimal(baseScore * exploitability * remediationLevel * reportConfidence)
    }

    override fun calculateEnvironmentalScore(): Double {
        val adjustedImpact =
            min(
                10.0,
                10.41 *
                    (1.0 -
                        (1.0 - confidentialityImpact * confidentialityRequirement) *
                            (1.0 - integrityImpact * integrityRequirement) *
                            (1.0 - availabilityImpact * availabilityRequirement))
            )
        val adjustedBaseScore = baseScoreForImpact(adjustedImpact)
        val adjustedTemporal =
            roundTo1Decimal(
                adjustedBaseScore * exploitability * remediationLevel * reportConfidence
            )
        return roundTo1Decimal(
            (adjustedTemporal + (10.0 - adjustedTemporal) * collateralDamagePotential) *
                targetDistribution
        )
    }

    fun roundTo1Decimal(x: Double): Double = round(x * 10.0) / 10.0

    companion object {
        fun fromVectorString(vec: String): CvssV2Calculation {
            return CvssV2Calculation(vec.toCvssMetrics(allowedVersions = null))
        }
    }
}
