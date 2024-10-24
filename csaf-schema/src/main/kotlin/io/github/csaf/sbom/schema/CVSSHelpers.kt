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

fun ceil(x: Double, digits: Int): Double {
    val factor = 10.0.pow(digits)
    return ceil(x * factor) / factor
}
