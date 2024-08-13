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
package com.github.csaf.validation.roles

import com.github.csaf.validation.*
import com.github.csaf.validation.requirements.*

open class CSAFPublisherRole : Role() {

    override val requirements = allOf(ValidCSAFDocument, ValidFilename)
}

open class CSAFProviderRole : CSAFPublisherRole() {
    override val requirements: Requirement
        get() =
            super.requirements +
                oneOf(Requirement8, Requirement9, Requirement10) +
                (allOf(Requirement11, Requirement12, Requirement13, Requirement14) or
                    allOf(Requirement15, Requirement16, Requirement17))
}

class CSAFTrustedProviderRole : CSAFProviderRole() {
    override val requirements: Requirement
        get() = super.requirements + allOf(Requirement18, Requirement19, Requirement20)
}

open class CSAFListerRole : Role() {
    override var requirements: Requirement = ValidCSAFDocument
}

class CSAFAggregatorRole : CSAFListerRole()
