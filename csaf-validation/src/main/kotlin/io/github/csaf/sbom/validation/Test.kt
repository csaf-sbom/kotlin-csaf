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
package io.github.csaf.sbom.validation

import io.github.csaf.sbom.schema.generated.Csaf

/**
 * Represents a test as described in
 * [Section 6](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6-tests). They all
 * target a CSAF document, represented by the [Csaf] type.
 */
interface Test {

    fun test(doc: Csaf): ValidationResult
}