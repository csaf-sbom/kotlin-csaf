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
        var ex =
            assertFailsWith<IllegalArgumentException> { CvssV3Calculation.fromVectorString("") }
        assertNotNull(ex)
        assertEquals("Invalid CVSS format or version", ex.message)

        ex = assertFailsWith<IllegalArgumentException> { CvssV3Calculation.fromVectorString("a/b") }
        assertNotNull(ex)
        assertEquals("Invalid CVSS format or version", ex.message)

        ex =
            assertFailsWith<IllegalArgumentException> {
                CvssV3Calculation.fromVectorString("CVSS:3.2")
            }
        assertNotNull(ex)
        assertEquals("Invalid CVSS format or version", ex.message)

        ex =
            assertFailsWith<IllegalArgumentException> {
                CvssV3Calculation.fromVectorString("CVSS:3.0/b")
            }
        assertNotNull(ex)
        assertEquals("Value for b is missing", ex.message)

        ex =
            assertFailsWith<IllegalArgumentException> {
                CvssV3Calculation.fromVectorString("CVSS:3.0/AC:L/AC:H")
            }
        assertNotNull(ex)
        assertEquals("Metric AC already defined", ex.message)

        ex =
            assertFailsWith<IllegalArgumentException> {
                CvssV3Calculation.fromVectorString("CVSS:3.0/AC:H")
            }
        assertNotNull(ex)
        assertEquals("Required property not present: scope", ex.message)

        ex =
            assertFailsWith<IllegalArgumentException> {
                CvssV3Calculation.fromVectorString("CVSS:3.0/AV:N/AC:X/PR:L/UI:N/S:C/C:L/I:L/A:L")
            }
        assertNotNull(ex)
        assertEquals("Invalid value: X in attackComplexity", ex.message)
    }

    @Test
    fun testCalculateBaseScore() {
        var metrics =
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
            )
        var score = metrics.baseScore
        assertEquals(Csaf.BaseSeverity.MEDIUM, metrics.baseSeverity)
        assertEquals(6.1, score)

        metrics =
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
            )
        assertEquals(3.1, metrics.baseScore)
        assertEquals(Csaf.BaseSeverity.LOW, metrics.baseSeverity)

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L
        metrics = CvssV3Calculation.fromVectorString("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L")
        assertEquals(7.4, metrics.baseScore)
        assertEquals(Csaf.BaseSeverity.HIGH, metrics.baseSeverity)

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
        metrics = CvssV3Calculation.fromVectorString("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assertEquals(0.0, metrics.baseScore)
        assertEquals(Csaf.BaseSeverity.NONE, metrics.baseSeverity)

        // https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/RL:W
        metrics =
            CvssV3Calculation.fromVectorString("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/RL:W")
        assertEquals(6.1, metrics.baseScore)
        assertEquals(Csaf.BaseSeverity.MEDIUM, metrics.baseSeverity)
    }

    @Test
    fun testTemporalScore() {
        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U
        var metrics =
            CvssV3Calculation.fromVectorString(
                "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U"
            )
        var score = metrics.calculateTemporalScore()
        assertEquals(4.7, score)
        assertEquals(Csaf.BaseSeverity.MEDIUM, metrics.temporalSeverity)

        // https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U
        metrics =
            CvssV3Calculation.fromVectorString(
                "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U"
            )
        assertEquals(4.6, metrics.temporalScore)
        assertEquals(Csaf.BaseSeverity.MEDIUM, metrics.temporalSeverity)
    }

    @Test
    fun testCalculateEnvironmentalScore() {
        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
        var metrics =
            CvssV3Calculation.fromVectorString("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assertEquals(0.0, metrics.environmentalScore)
        assertEquals(Csaf.BaseSeverity.NONE, metrics.environmentalSeverity)

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
        metrics = CvssV3Calculation.fromVectorString("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assertEquals(7.5, metrics.environmentalScore)
        assertEquals(Csaf.BaseSeverity.HIGH, metrics.environmentalSeverity)

        // https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H
        metrics =
            CvssV3Calculation.fromVectorString(
                "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"
            )
        assertEquals(5.5, metrics.environmentalScore)
        assertEquals(Csaf.BaseSeverity.MEDIUM, metrics.environmentalSeverity)

        // https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H
        metrics =
            CvssV3Calculation.fromVectorString(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H"
            )
        assertEquals(5.6, metrics.environmentalScore)
        assertEquals(Csaf.BaseSeverity.MEDIUM, metrics.environmentalSeverity)
    }
}
