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

import io.github.csaf.sbom.schema.cvss.common.toSeverity
import io.github.csaf.sbom.schema.cvss.v30.CVSS30Metrics
import io.github.csaf.sbom.schema.cvss.v30.calculateEnvironmentalScore
import io.github.csaf.sbom.schema.cvss.v30.calculateTemporalScore
import io.github.csaf.sbom.schema.generated.CvssV30
import io.github.csaf.sbom.schema.generated.CvssV30.ConfidentialityImpact
import io.github.csaf.sbom.schema.generated.CvssV30.Scope
import kotlin.math.ceil
import kotlin.math.pow
import kotlin.reflect.KProperty1

typealias MetricShortName = String

fun CvssV30.Companion.fromVectorString(vec: String): CvssV30? {
    // First, father all the metrics
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
            scope = metrics.scope,
            availabilityImpact = metrics.availabilityImpact,
            confidentialityImpact = metrics.confidentialityImpact,
            integrityImpact = metrics.integrityImpact,
            attackVector = metrics.attackVector,
            attackComplexity = metrics.attackComplexity,
            privilegesRequired = metrics.privilegesRequired,
            userInteraction = metrics.userInteraction
        )

    return score
}

fun calculateImpact(
    scope: Scope,
    confidentialityImpact: ConfidentialityImpact,
    integrityImpact: ConfidentialityImpact,
    availabilityImpact: ConfidentialityImpact
): Double {
    val iscBase =
        1.0 - ((1.0 - confidentialityImpact) * (1.0 - integrityImpact) * (1.0 - availabilityImpact))
    return if (scope == Scope.UNCHANGED) {
        6.42 * iscBase
    } else {
        7.52 * (iscBase - 0.029) - 3.52 * (iscBase - 0.02).pow(15)
    }
}

/**
 * A list of metric properties, that if specified "delegate" the metric value to their base value
 */
val notDefinedDelegates =
    mapOf(
        CVSS30Metrics::modifiedAttackVector to
            Pair(CvssV30.ModifiedAttackVector.NOT_DEFINED, CVSS30Metrics::attackVector),
        CVSS30Metrics::modifiedAttackComplexity to
            Pair(CvssV30.ModifiedAttackComplexity.NOT_DEFINED, CVSS30Metrics::attackComplexity),
        CVSS30Metrics::modifiedPrivilegesRequired to
            Pair(CvssV30.ModifiedPrivilegesRequired.NOT_DEFINED, CVSS30Metrics::privilegesRequired),
        CVSS30Metrics::modifiedUserInteraction to
            Pair(CvssV30.ModifiedUserInteraction.NOT_DEFINED, CVSS30Metrics::userInteraction),
        CVSS30Metrics::modifiedConfidentialityImpact to
            Pair(
                CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
                CVSS30Metrics::confidentialityImpact
            ),
        CVSS30Metrics::modifiedIntegrityImpact to
            Pair(CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED, CVSS30Metrics::integrityImpact),
        CVSS30Metrics::modifiedAvailabilityImpact to
            Pair(
                CvssV30.ModifiedConfidentialityImpact.NOT_DEFINED,
                CVSS30Metrics::availabilityImpact
            ),
    )

// TODO(oxisto): maybe we can convert this into a delegate
fun CVSS30Metrics.checkForNotDefined(property: KProperty1<CVSS30Metrics, Enum<*>?>): Double {
    // Retrieve the value
    val value = property.get(this)
    if (value == null) {
        throw IllegalArgumentException("value must not be null")
    }

    // Check, if this value is set to "not defined", so we need to delegate it to the base property
    val delegatedProperty = notDefinedDelegates[property]
    return if (delegatedProperty != null && value == delegatedProperty.first) {
        delegatedProperty.second.get(this).numericalValue()
    } else {
        // Otherwise, let's try our luck
        value.numericalValue()
    }
}

operator fun Double.minus(value: Enum<*>): Double {
    return this - value.numericalValue()
}

operator fun Double.times(value: Enum<*>): Double {
    return this * value.numericalValue()
}

operator fun Enum<*>.times(value: Enum<*>): Double {
    return this.numericalValue() * value.numericalValue()
}

operator fun Enum<*>.times(value: Double): Double {
    return this.numericalValue() * value
}

fun calculateExploitability(
    attackVector: CvssV30.AttackVector,
    attackComplexity: CvssV30.AttackComplexity,
    privilegesRequired: CvssV30.PrivilegesRequired,
    userInteraction: CvssV30.UserInteraction
): Double {
    return 8.22 *
        attackVector.numericalValue() *
        attackComplexity.numericalValue() *
        privilegesRequired.numericalValue() *
        userInteraction.numericalValue()
}

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
                "H" to ConfidentialityImpact.HIGH,
                "L" to ConfidentialityImpact.LOW,
                "N" to ConfidentialityImpact.NONE,
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

inline fun <reified T : Enum<*>> Map<MetricShortName, String>.valueOf(
    prop: KProperty1<CvssV30, T?>,
    required: Boolean = false
): T {
    // First, find out the short name
    val shortName = shortNames[prop]

    if (shortName == null) {
        throw IllegalArgumentException("invalid property: ${prop.name}")
    }

    var stringValue = this[shortName]
    if (stringValue == null && required) {
        throw IllegalArgumentException("required property not present: ${prop.name}")
    } else if (stringValue == null) {
        stringValue = "X"
    }

    val value = valueMapping[T::class]?.get(stringValue)
    if (value == null) {
        throw IllegalArgumentException("invalid value: $stringValue")
    }

    return value as T
}

inline fun <reified T : Enum<*>> metricLevel(x: T): Map<Enum<*>, Double> {
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
        else -> throw IllegalArgumentException("invalid enum class: ${x::class.simpleName}")
    }
}

inline fun <reified T : Enum<*>> T.numericalValue(): Double {
    val mapping = metricLevel(this)
    return mapping[this]
        ?: throw IllegalArgumentException("unknown value: $this of ${this::class.simpleName}")
}

fun ceil(x: Double, digits: Int): Double {
    val factor = 10.0.pow(digits)
    return ceil(x * factor) / factor
}
