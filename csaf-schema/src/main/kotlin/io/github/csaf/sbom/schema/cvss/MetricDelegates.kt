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
import io.github.csaf.sbom.schema.cvss.v30.valueMapping
import io.github.csaf.sbom.schema.numericalValue
import kotlin.reflect.KClass
import kotlin.reflect.KProperty
import kotlin.reflect.KProperty1

class ModifiedMetricDelegate<
    ModifiedPropertyEnum : Enum<*>,
    BasePropertyEnum : Enum<*>,
    Metrics : CVSSMetrics
>(
    var value: ModifiedPropertyEnum,
    var notDefinedValue: ModifiedPropertyEnum,
    var baseProperty: KProperty1<Metrics, BasePropertyEnum>
) {
    operator fun getValue(thisRef: Metrics, property: KProperty<*>): Enum<*> {
        // If our value is equal to "not defined", we need to delegate to our base property
        if (value == notDefinedValue) {
            return baseProperty.get(thisRef)
        }

        // Otherwise, we can return the value
        return value
    }
}

class ModifiedMetricDelegate2<
    ModifiedPropertyEnum : Enum<ModifiedPropertyEnum>,
    BasePropertyEnum : Enum<BasePropertyEnum>,
    Metrics : CVSSMetrics
>(
    var shortName: MetricShortName,
    var propertyType: KClass<ModifiedPropertyEnum>,
    var notDefinedValue: ModifiedPropertyEnum,
    var baseProperty: KProperty1<Metrics, BaseMetric<BasePropertyEnum>>
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

interface Metric<PropertyEnum : Enum<PropertyEnum>> {
    val numericalValue: Double
    val enumValue: PropertyEnum
}

data class BaseMetric<PropertyEnum : Enum<PropertyEnum>>(override val enumValue: PropertyEnum) :
    Metric<PropertyEnum> {
    override val numericalValue: Double
        get() {
            return enumValue.numericalValue()
        }
}

class ModifiedMetric<PropertyEnum : Enum<PropertyEnum>>(
    /** The enum value of this metric, as defined in [PropertyEnum]. */
    override val enumValue: PropertyEnum,

    /** The value of [PropertyEnum] that specifies the "not defined" state. */
    val notDefinedValue: PropertyEnum,

    /**
     * The value of the associated "base" metrics, that is used as a fallback, if the modified
     * metric is not defined.
     */
    val baseValue: Metric<*>
) : Metric<PropertyEnum> {
    override val numericalValue: Double
        get() =
            if (enumValue == notDefinedValue) {
                baseValue.numericalValue
            } else {
                enumValue.numericalValue()
            }
}

open class BaseMetricDelegate<PropertyEnum : Enum<PropertyEnum>>(
    val shortName: MetricShortName,
    val propertyType: KClass<out PropertyEnum>,
    val required: Boolean = true
) {
    operator fun getValue(thisRef: CVSSMetrics, property: KProperty<*>): BaseMetric<PropertyEnum> {
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

        @Suppress("UNCHECKED_CAST") return BaseMetric(value as PropertyEnum)
    }
}

fun <
    ModifiedPropertyEnum : Enum<*>,
    BasePropertyEnum : Enum<*>,
    Metrics : CVSSMetrics
> modifiedMetric(
    value: ModifiedPropertyEnum,
    notDefinedValue: ModifiedPropertyEnum,
    property: KProperty1<Metrics, BasePropertyEnum>
) = ModifiedMetricDelegate(value, notDefinedValue, property)

inline fun <
    reified ModifiedPropertyEnum : Enum<ModifiedPropertyEnum>,
    BasePropertyEnum : Enum<BasePropertyEnum>,
    Metrics : CVSSMetrics
> modifiedMetric2(
    shortName: MetricShortName,
    notDefinedValue: ModifiedPropertyEnum,
    property: KProperty1<Metrics, BaseMetric<BasePropertyEnum>>
) =
    ModifiedMetricDelegate2<ModifiedPropertyEnum, BasePropertyEnum, Metrics>(
        shortName,
        ModifiedPropertyEnum::class,
        notDefinedValue,
        property
    )

inline fun <reified PropertyEnum : Enum<PropertyEnum>> requiredMetric(
    shortName: MetricShortName,
) = BaseMetricDelegate<PropertyEnum>(shortName, PropertyEnum::class, true)

inline fun <reified PropertyEnum : Enum<PropertyEnum>> optionalMetric(
    shortName: MetricShortName,
) = BaseMetricDelegate<PropertyEnum>(shortName, PropertyEnum::class, false)
