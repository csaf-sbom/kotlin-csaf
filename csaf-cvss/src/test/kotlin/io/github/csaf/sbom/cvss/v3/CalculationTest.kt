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
package io.github.csaf.sbom.cvss.v3

import io.github.csaf.sbom.schema.generated.Csaf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class CalculationTest {

    @Test
    fun testFromVectorString() {
        fun assertInvalidVectorString(vector: String, expectedMessage: String) {
            val exception =
                assertFailsWith<IllegalArgumentException> {
                    CvssV3Calculation.fromVectorString(vector)
                }
            assertNotNull(exception)
            assertEquals(expectedMessage, exception.message)
        }

        assertInvalidVectorString("", "Invalid CVSS format or version")
        assertInvalidVectorString("a/b", "Invalid CVSS format or version")
        assertInvalidVectorString("CVSS:3.2", "Invalid CVSS format or version")
        assertInvalidVectorString("CVSS:3.0/b", "Value for b is missing")
        assertInvalidVectorString("CVSS:3.0/AC:L/AC:H", "Metric AC already defined")
        assertInvalidVectorString("CVSS:3.0/AC:H", "Required property not present: scope")
        assertInvalidVectorString(
            "CVSS:3.0/AV:N/AC:X/PR:L/UI:N/S:C/C:L/I:L/A:L",
            "Invalid value: X in attackComplexity"
        )
    }

    @Test
    fun testCalculateBaseScore() {
        fun verifyMetrics(
            metrics: CvssV3Calculation,
            expectedSeverity: Csaf.BaseSeverity,
            expectedScore: Double
        ) {
            assertEquals(expectedSeverity, metrics.baseSeverity)
            assertEquals(expectedScore, metrics.baseScore)
        }

        verifyMetrics(
            CvssV3Calculation(
                metrics =
                    mapOf(
                        "S" to "C",
                        "C" to "L",
                        "I" to "L",
                        "A" to "N",
                        "AV" to "N",
                        "AC" to "L",
                        "PR" to "N",
                        "UI" to "R",
                    )
            ),
            Csaf.BaseSeverity.MEDIUM,
            6.1
        )

        verifyMetrics(
            CvssV3Calculation(
                metrics =
                    mapOf(
                        "S" to "U",
                        "C" to "L",
                        "I" to "N",
                        "A" to "N",
                        "AV" to "N",
                        "AC" to "H",
                        "PR" to "N",
                        "UI" to "R",
                    )
            ),
            Csaf.BaseSeverity.LOW,
            3.1
        )

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L
        verifyMetrics(
            CvssV3Calculation.fromVectorString("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L"),
            Csaf.BaseSeverity.HIGH,
            7.4
        )

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
        verifyMetrics(
            CvssV3Calculation.fromVectorString("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            Csaf.BaseSeverity.NONE,
            0.0
        )

        // https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/RL:W
        verifyMetrics(
            CvssV3Calculation.fromVectorString("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/RL:W"),
            Csaf.BaseSeverity.MEDIUM,
            6.1
        )
    }

    @Test
    fun testTemporalScore() {
        fun verifyTemporalScore(
            vectorString: String,
            expectedScore: Double,
            expectedSeverity: Csaf.BaseSeverity
        ) {
            val metrics = CvssV3Calculation.fromVectorString(vectorString)
            assertEquals(expectedScore, metrics.temporalScore)
            assertEquals(expectedSeverity, metrics.temporalSeverity)
        }

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U
        verifyTemporalScore(
            "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U",
            4.7,
            Csaf.BaseSeverity.MEDIUM
        )

        // https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U
        verifyTemporalScore(
            "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U",
            4.6,
            Csaf.BaseSeverity.MEDIUM
        )
    }

    @Test
    fun testCalculateEnvironmentalScore() {
        fun verifyEnvironmentalScore(
            vectorString: String,
            expectedScore: Double,
            expectedSeverity: Csaf.BaseSeverity
        ) {
            val metrics = CvssV3Calculation.fromVectorString(vectorString)
            assertEquals(expectedScore, metrics.environmentalScore)
            assertEquals(expectedSeverity, metrics.environmentalSeverity)
        }

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
        verifyEnvironmentalScore(
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            0.0,
            Csaf.BaseSeverity.NONE
        )

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
        verifyEnvironmentalScore(
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            7.5,
            Csaf.BaseSeverity.HIGH
        )

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H
        verifyEnvironmentalScore(
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
            5.5,
            Csaf.BaseSeverity.MEDIUM
        )

        // https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H
        verifyEnvironmentalScore(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
            5.6,
            Csaf.BaseSeverity.MEDIUM
        )

        // Almost identical vector compared to the one above, but with "MS:X" to check the scope
        // "fallback" to "S:C".
        verifyEnvironmentalScore(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:X/MC:H/MI:H/MA:H",
            5.6,
            Csaf.BaseSeverity.MEDIUM
        )
    }
}
