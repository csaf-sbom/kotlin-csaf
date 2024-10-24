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
import io.github.csaf.sbom.schema.cvss.v30.metricLevel
import io.github.csaf.sbom.schema.cvss.v30.valueMapping
import kotlin.reflect.KClass
import kotlin.reflect.KProperty
import kotlin.reflect.KProperty1

class ModifiedMetricDelegate<
    ModifiedPropertyEnum : Enum<ModifiedPropertyEnum>,
    BasePropertyEnum : Enum<BasePropertyEnum>,
    Metrics : CVSSMetrics
>(
    var shortName: MetricShortName,
    var propertyType: KClass<ModifiedPropertyEnum>,
    var notDefinedValue: ModifiedPropertyEnum,
    var baseProperty: KProperty1<Metrics, Metric<BasePropertyEnum>>
) {
    operator fun getValue(thisRef: Metrics, property: KProperty<*>): Metric<ModifiedPropertyEnum> {
        // First, find out the short name
        var stringValue = thisRef.metrics[shortName]
        if (stringValue == null) {
            stringValue = "X"
        }

        val value = valueMapping[propertyType]?.get(stringValue)
        if (value == null) {
            throw IllegalArgumentException("invalid value: $stringValue")
        }

        @Suppress("UNCHECKED_CAST")
        return ModifiedMetric(
            value as ModifiedPropertyEnum,
            notDefinedValue,
            baseProperty.get(thisRef)
        )
    }
}

open class Metric<PropertyEnum : Enum<PropertyEnum>>(
    /** The enum value of this metric, as defined in [PropertyEnum]. */
    val enumValue: PropertyEnum
) {
    open val numericalValue: Double
        get() {
            val mapping = metricLevel(enumValue)
            return mapping[enumValue::class as Enum<*>]
                ?: throw IllegalArgumentException(
                    "unknown value: $this of ${this::class.simpleName}"
                )
        }
}

class ModifiedMetric<PropertyEnum : Enum<PropertyEnum>>(
    /** The enum value of this metric, as defined in [PropertyEnum]. */
    enumValue: PropertyEnum,

    /** The value of [PropertyEnum] that specifies the "not defined" state. */
    val notDefinedValue: PropertyEnum,

    /**
     * The value of the associated "base" metrics, that is used as a fallback, if the modified
     * metric is not defined.
     */
    val baseValue: Metric<*>
) : Metric<PropertyEnum>(enumValue) {
    override val numericalValue: Double
        get() =
            if (enumValue == notDefinedValue) {
                baseValue.numericalValue
            } else {
                super.numericalValue
            }
}

open class MetricDelegate<PropertyEnum : Enum<PropertyEnum>>(
    val shortName: MetricShortName,
    val propertyType: KClass<out PropertyEnum>,
    val required: Boolean = true
) {
    operator fun getValue(thisRef: CVSSMetrics, property: KProperty<*>): Metric<PropertyEnum> {
        // First, find out the short name
        var stringValue = thisRef.metrics[shortName]
        if (stringValue == null && required) {
            throw IllegalArgumentException("required property not present: ${property.name}")
        } else if (stringValue == null) {
            stringValue = "X"
        }

        val value = valueMapping[propertyType]?.get(stringValue)
        if (value == null) {
            throw IllegalArgumentException("invalid value: $stringValue")
        }

        @Suppress("UNCHECKED_CAST") return Metric(value as PropertyEnum)
    }
}

inline fun <
    reified ModifiedPropertyEnum : Enum<ModifiedPropertyEnum>,
    BasePropertyEnum : Enum<BasePropertyEnum>,
    Metrics : CVSSMetrics
> modifiedMetric(
    shortName: MetricShortName,
    notDefinedValue: ModifiedPropertyEnum,
    property: KProperty1<Metrics, Metric<BasePropertyEnum>>
) =
    ModifiedMetricDelegate<ModifiedPropertyEnum, BasePropertyEnum, Metrics>(
        shortName,
        ModifiedPropertyEnum::class,
        notDefinedValue,
        property
    )

inline fun <reified PropertyEnum : Enum<PropertyEnum>> requiredMetric(
    shortName: MetricShortName,
) = MetricDelegate<PropertyEnum>(shortName, PropertyEnum::class, true)

inline fun <reified PropertyEnum : Enum<PropertyEnum>> optionalMetric(
    shortName: MetricShortName,
) = MetricDelegate<PropertyEnum>(shortName, PropertyEnum::class, false)
