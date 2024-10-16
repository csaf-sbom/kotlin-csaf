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
package io.github.csaf.sbom.validation.tests

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.validation.Test
import io.github.csaf.sbom.validation.ValidationFailed
import io.github.csaf.sbom.validation.ValidationResult
import io.github.csaf.sbom.validation.ValidationSuccessful

object Test611MissingDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProducts().map { it.product_id }
        val references = doc.gatherProductReferences()

        println(
            "Gathered ${definitions.size} product ID definitions and ${references.size} product ID references"
        )

        val notDefined = references.subtract(definitions)

        return if (notDefined.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are not defined: ${notDefined.joinToString(",")}")
            )
        }
    }
}

object Test621UnusedDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProducts().map { it.product_id }
        val references = doc.gatherProductReferences()

        println(
            "Gathered ${definitions.size} product ID definitions and ${references.size} product ID references"
        )

        val notUsed = definitions.subtract(references)
        return if (notUsed.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("The following IDs are not used: ${notUsed.joinToString(",")}"))
        }
    }
}
