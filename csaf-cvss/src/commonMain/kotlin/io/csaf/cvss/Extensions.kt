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
package io.csaf.cvss

import io.csaf.schema.generated.Csaf.BaseSeverity

@Suppress("KotlinConstantConditions")
fun Double.toSeverity(): BaseSeverity {
    return when {
        this == 0.0 -> BaseSeverity.NONE
        this < 4.0 -> BaseSeverity.LOW
        this < 7.0 -> BaseSeverity.MEDIUM
        this < 9.0 -> BaseSeverity.HIGH
        this <= 10.0 -> BaseSeverity.CRITICAL
        else -> throw IllegalArgumentException("invalid score")
    }
}

operator fun Double.minus(value: MetricValue<*>): Double {
    return this - value.numericalValue
}

operator fun Double.times(value: MetricValue<*>): Double {
    return this * value.numericalValue
}

operator fun MetricValue<*>.times(value: MetricValue<*>): Double {
    return this.numericalValue * value.numericalValue
}

/**
 * Converts this vector string into a map of CVSS metrics. The [allowedVersions] list must be
 * specified if the standard is 3.X.
 */
fun String.toCvssMetrics(allowedVersions: List<String>?): MutableMap<String, String> {
    // Split the vector into parts
    val parts = this.split("/")

    // A map of metrics and their values.
    val metrics = mutableMapOf<String, String>()

    for ((idx, part) in parts.withIndex()) {
        val keyValue = part.split(":")
        val key = keyValue.first()
        val value = keyValue.getOrNull(1)

        // Allowed versions are only applicable for CVSS 3.X
        if (allowedVersions != null) {
            if (idx == 0 && (key != "CVSS" || (value !in allowedVersions))) {
                // First key must be CVSS:3.X
                throw IllegalArgumentException("Invalid CVSS format or version")
            }
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

    return metrics
}
