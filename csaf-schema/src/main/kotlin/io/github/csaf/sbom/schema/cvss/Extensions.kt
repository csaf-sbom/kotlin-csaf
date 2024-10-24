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
package io.github.csaf.sbom.schema.cvss

import io.github.csaf.sbom.schema.MetricShortName
import io.github.csaf.sbom.schema.generated.CvssV30

fun Double.toSeverity(): CvssV30.BaseSeverity {
    return when {
        this == 0.0 -> CvssV30.BaseSeverity.NONE
        this < 4.0 -> CvssV30.BaseSeverity.LOW
        this < 7.0 -> CvssV30.BaseSeverity.MEDIUM
        this < 9.0 -> CvssV30.BaseSeverity.HIGH
        this <= 10.0 -> CvssV30.BaseSeverity.CRITICAL
        else -> throw IllegalArgumentException("invalid score")
    }
}

operator fun Double.minus(value: Metric<*>): Double {
    return this - value.numericalValue
}

operator fun Double.times(value: Metric<*>): Double {
    return this * value.numericalValue
}

operator fun Metric<*>.times(value: Metric<*>): Double {
    return this.numericalValue * value.numericalValue
}

operator fun Metric<*>.times(value: Double): Double {
    return this.numericalValue * value
}

interface CVSSMetrics {

    val metrics: Map<MetricShortName, String>

    fun calculateBaseScore(): Double
}
