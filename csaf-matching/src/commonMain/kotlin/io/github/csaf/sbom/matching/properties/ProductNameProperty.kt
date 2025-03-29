/*
 * Copyright (c) 2025, The Authors. All rights reserved.
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
package io.github.csaf.sbom.matching.properties

import io.github.csaf.sbom.matching.Cpe
import io.github.csaf.sbom.matching.Purl
import io.github.csaf.sbom.matching.VulnerableProduct
import io.github.csaf.sbom.schema.generated.Csaf
import protobom.protobom.Node

/** A property that presents a product name. */
typealias ProductNameProperty = StringProperty

/**
 * The [ProductNamePropertyProvider] is a [PropertyProvider] that provides the name of a product as
 * a [ProductNameProperty].
 *
 * It extracts the vendor from the [VulnerableProduct.branches] or [Cpe] and returns it as a
 * [ProductNameProperty].
 */
object ProductNamePropertyProvider : PropertyProvider<ProductNameProperty> {
    override fun provideProperty(vulnerable: VulnerableProduct): ProductNameProperty? {
        return vulnerable.branches
            .firstOrNull { it.category == Csaf.Category3.product_name }
            ?.name
            ?.toProperty(PropertySource.OTHER)
    }

    override fun provideProperty(node: Node): ProductNameProperty? {
        return node.name.toProperty(PropertySource.OTHER)
    }

    override fun provideProperty(cpe: Cpe): ProductNameProperty? {
        return cpe.getProduct().toProperty(PropertySource.CPE)
    }

    override fun provideProperty(purl: Purl): ProductNameProperty? {
        return purl.getName().toProperty(PropertySource.PURL)
    }
}
