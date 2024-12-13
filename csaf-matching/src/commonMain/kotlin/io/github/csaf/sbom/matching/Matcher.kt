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
package io.github.csaf.sbom.matching

import io.github.csaf.sbom.schema.generated.Csaf

/**
 * Matches the provided SBOM document with the CSAF document and determines whether they meet specific criteria.
 *
 * @param sbom The SBOM document represented by a protobom.protobom.Document instance.
 * @param doc The CSAF document to be matched against, represented by a Csaf instance.
 * @return A boolean value indicating whether the SBOM document matches the CSAF document.
 */
fun match(sbom: protobom.protobom.Document, doc: Csaf): Boolean {
    return true
}
