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
package io.github.csaf.sbom.schema.cvss.v30

import io.github.csaf.sbom.schema.generated.CvssV30
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test

class CalculationTest {

    @Test
    fun testCalculateBaseScore() {
        var metrics =
            CVSS30Metrics(
                scope = CvssV30.Scope.CHANGED,
                confidentialityImpact = CvssV30.ConfidentialityImpact.LOW,
                integrityImpact = CvssV30.ConfidentialityImpact.LOW,
                availabilityImpact = CvssV30.ConfidentialityImpact.NONE,
                attackVector = CvssV30.AttackVector.NETWORK,
                attackComplexity = CvssV30.AttackComplexity.LOW,
                privilegesRequired = CvssV30.PrivilegesRequired.NONE,
                userInteraction = CvssV30.UserInteraction.REQUIRED,
            )
        var score = metrics.calculateBaseScore()
        assertEquals(6.1, score)

        metrics =
            CVSS30Metrics(
                scope = CvssV30.Scope.UNCHANGED,
                confidentialityImpact = CvssV30.ConfidentialityImpact.LOW,
                integrityImpact = CvssV30.ConfidentialityImpact.NONE,
                availabilityImpact = CvssV30.ConfidentialityImpact.NONE,
                attackVector = CvssV30.AttackVector.NETWORK,
                attackComplexity = CvssV30.AttackComplexity.HIGH,
                privilegesRequired = CvssV30.PrivilegesRequired.NONE,
                userInteraction = CvssV30.UserInteraction.REQUIRED,
            )
        score = metrics.calculateBaseScore()
        assertEquals(3.1, score)
    }
}
