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
package io.github.csaf.sbom.matching

import io.github.csaf.sbom.schema.generated.Csaf
import protobom.protobom.Node

/**
 * A data class representing a match between an [Csaf.Product] to a SBOM [Node] with given
 * [MatchingConfidence].
 *
 * @property advisory The matched CSAF advisory.
 * @property vulnerableProduct The vulnerable product from the CSAF advisory.
 * @property affectedNode The affected component from the SBOM document.
 * @property confidence The confidence score of the match.
 * @constructor Creates CSAF-SBOM-match with given score.
 */
data class Match(
    val advisory: Csaf,
    val vulnerableProduct: Csaf.Product,
    val affectedNode: Node,
    val confidence: MatchingConfidence,
)
