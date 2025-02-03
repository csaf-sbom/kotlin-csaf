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

/**
 * A data class representing a CSAF-SBOM-match with associated score in [0.0; 1.0].
 *
 * @property csaf The matched CSAF document.
 * @property score The matching score in the interval [0.0; 1.0].
 * @constructor Creates CSAF-SBOM-match with given score.
 */
data class Match(val csaf: Csaf, val score: Float) {
    init {
        require(score in 0.0..1.0) { "Score must be in the interval [0.0; 1.0]." }
    }
}
