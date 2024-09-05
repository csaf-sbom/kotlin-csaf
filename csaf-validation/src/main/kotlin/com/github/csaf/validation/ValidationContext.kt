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
package com.github.csaf.validation

import io.github.csaf.sbom.generated.Aggregator
import io.github.csaf.sbom.generated.Csaf.Document
import io.github.csaf.sbom.generated.Provider

/** This class holds all necessary information that are needed to be checked by a [Requirement]. */
class ValidationContext {
    // TODO: add members to be accessed by the requirements
    // TODO: this is probably not the final context, we probably want to have sub-contexts
    var aggregator: Aggregator? = null
    var provider: Provider? = null
    var document: Document? = null
}
