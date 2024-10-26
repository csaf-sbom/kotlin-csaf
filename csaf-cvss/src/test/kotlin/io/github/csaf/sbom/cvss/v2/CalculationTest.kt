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
package io.github.csaf.sbom.cvss.v2

import kotlin.test.Test
import kotlin.test.assertEquals

class CalculationTest {
    @Test
    fun testCalculateBaseScore() {
        // https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(AV:N/AC:M/Au:N/C:C/I:C/A:N/E:POC/RL:W/RC:C/CDP:N/TD:M/CR:ND/IR:ND/AR:ND)
        val calc =
            CvssV2Calculation.fromVectorString(
                "AV:N/AC:M/Au:N/C:C/I:C/A:N/E:POC/RL:W/RC:C/CDP:N/TD:M/CR:ND/IR:ND/AR:ND"
            )
        val score = calc.calculateBaseScore()
        assertEquals(8.8, score)
    }
}
