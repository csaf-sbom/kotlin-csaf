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

object Test612MultipleDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProducts().map { it.product_id }

        val duplicates = definitions.groupingBy { it }.eachCount().filter { it.value > 1 }

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are duplicate: ${duplicates.keys.joinToString(",")}")
            )
        }
    }
}

object Test613CircularDefinitionOfProductID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val circles = mutableSetOf<String>()

        for (relationship in doc.product_tree?.relationships ?: listOf()) {
            var definedId = relationship.full_product_name.product_id
            var notAllowed =
                listOf(relationship.product_reference, relationship.relates_to_product_reference)
            if (definedId in notAllowed) {
                circles += definedId
            }
        }

        return if (circles.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are defined in circles: ${circles.joinToString(",")}")
            )
        }
    }
}

object Test614MissingDefinitionOfProductGroupID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProductGroups().map { it.group_id }
        val references = doc.gatherProductGroupReferences()

        println(
            "Gathered ${definitions.size} product group ID definitions and ${references.size} product group ID references"
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

object Test615MultipleDefinitionOfProductGroupID : Test {
    override fun test(doc: Csaf): ValidationResult {
        val definitions = doc.gatherProductGroups().map { it.group_id }

        val duplicates = definitions.groupingBy { it }.eachCount().filter { it.value > 1 }

        return if (duplicates.isEmpty()) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("The following IDs are duplicate: ${duplicates.keys.joinToString(",")}")
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
