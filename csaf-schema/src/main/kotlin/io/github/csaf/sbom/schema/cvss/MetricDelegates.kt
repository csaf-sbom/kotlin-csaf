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
import jdk.internal.platform.Container.metrics
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

class MetricDelegate<PropertyEnum : Enum<*>, Metrics : CVSSMetrics>(
    val shortName: MetricShortName,
    val propertyType: KClass<PropertyEnum>,
    val required: Boolean = true
) {
    operator fun getValue(thisRef: Metrics, property: KProperty<*>): Enum<*> {
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

        return value
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

fun <PropertyEnum : Enum<*>, Metrics : CVSSMetrics> metric(
    shortName: MetricShortName,
    propertyType: KClass<PropertyEnum>,
    required: Boolean = true
) = MetricDelegate<PropertyEnum, Metrics>(shortName, propertyType, required)
