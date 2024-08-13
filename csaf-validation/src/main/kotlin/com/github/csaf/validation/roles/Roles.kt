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

/**
 * The "CSAF publisher" role. See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#721-role-csaf-publisher.
 */
open class CSAFPublisherRole : Role {

    override val requirements = allOf(ValidCSAFDocument, ValidFilename)
}

/**
 * The "CSAF provider" role. See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#722-role-csaf-provider.
 */
open class CSAFProviderRole : CSAFPublisherRole() {
    override val requirements: Requirement
        get() =
            super.requirements +
                oneOf(Requirement8, Requirement9, Requirement10) +
                (allOf(Requirement11, Requirement12, Requirement13, Requirement14) or
                    allOf(Requirement15, Requirement16, Requirement17))
}

/**
 * The "CSAF trusted provider role".
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#723-role-csaf-trusted-provider.
 */
class CSAFTrustedProviderRole : CSAFProviderRole() {
    override val requirements: Requirement
        get() = super.requirements + allOf(Requirement18, Requirement19, Requirement20)
}

/**
 * The "CSAF lister role". See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#724-role-csaf-lister.
 */
open class CSAFListerRole : Role {
    override var requirements: Requirement = allOf(Requirement6, Requirement21, Requirement22)
}

/**
 * The "CSAF aggregator role". See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#725-role-csaf-aggregator.
 */
class CSAFAggregatorRole : CSAFListerRole() {
    override var requirements: Requirement =
        allOf(
            ValidCSAFDocument,
            ValidFilename,
            Requirement3,
            Requirement4,
            Requirement5,
            Requirement6
        ) + allOf(Requirement21, Requirement22, Requirement23)
}
