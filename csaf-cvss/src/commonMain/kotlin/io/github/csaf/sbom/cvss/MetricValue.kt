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
package io.github.csaf.sbom.cvss

import io.github.csaf.sbom.cvss.v2.CvssV2Calculation
import kotlin.reflect.KProperty

/**
 * Represents the value of a CVSS metric. This class should not be used directly, instead metrics
 * should be defined by [requiredMetric] and [optionalMetric].
 */
class MetricValue<PropertyEnum : Enum<PropertyEnum>>(
    /** The enum value of this metric, as defined in [PropertyEnum]. */
    val enumValue: PropertyEnum,

    /** The numeric value of this metric. */
    val numericalValue: Double,
)

internal open class MetricDelegate<PropertyEnum : Enum<PropertyEnum>>(
    val shortName: String,
    val required: Boolean = false,
    val mapOf: Map<PropertyEnum, Pair<String, Double>>,
) {
    open operator fun getValue(
        thisRef: CvssCalculation,
        property: KProperty<*>,
    ): MetricValue<PropertyEnum> {
        val entry = metricEntry(thisRef, property)

        return MetricValue(entry.key, entry.value.second)
    }

    protected fun metricEntry(
        thisRef: CvssCalculation,
        property: KProperty<*>,
    ): Map.Entry<PropertyEnum, Pair<String, Double>> {
        // First, find out the short name
        var stringValue = thisRef.metrics[shortName]
        if (stringValue == null && required) {
            throw IllegalArgumentException("Required property not present: ${property.name}")
        } else if (stringValue == null) {
            if (thisRef is CvssV2Calculation) {
                stringValue = "ND"
            } else {
                stringValue = "X"
            }
        }

        // Find the entry with the matching string value
        val entry = mapOf.entries.firstOrNull { it.value.first == stringValue }
        if (entry == null) {
            throw IllegalArgumentException("Invalid value: $stringValue in ${property.name}")
        }

        return entry
    }
}

/**
 * Creates the definition for a new CVSS metric that is *required* by the respective standard
 * version. Calculating a score when this metric is not present will result in a
 * [IllegalArgumentException].
 */
internal fun <PropertyEnum : Enum<PropertyEnum>> requiredMetric(
    shortName: String,
    mapOf: Map<PropertyEnum, Pair<String, Double>>,
) = MetricDelegate<PropertyEnum>(shortName, true, mapOf)

/**
 * Creates the definition for a new CVSS metric that is *optional* by the respective standard
 * version.
 */
internal fun <PropertyEnum : Enum<PropertyEnum>> optionalMetric(
    shortName: String,
    mapOf: Map<PropertyEnum, Pair<String, Double>>,
) = MetricDelegate<PropertyEnum>(shortName, false, mapOf)
