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
package io.github.csaf.validation.roles

import io.github.csaf.validation.Requirement
import io.github.csaf.validation.Role
import io.github.csaf.validation.allOf
import io.github.csaf.validation.none
import io.github.csaf.validation.oneOf
import io.github.csaf.validation.or
import io.github.csaf.validation.plus
import io.github.csaf.validation.requirements.Requirement10
import io.github.csaf.validation.requirements.Requirement12
import io.github.csaf.validation.requirements.Requirement13
import io.github.csaf.validation.requirements.Requirement14
import io.github.csaf.validation.requirements.Requirement15
import io.github.csaf.validation.requirements.Requirement16
import io.github.csaf.validation.requirements.Requirement17
import io.github.csaf.validation.requirements.Requirement18
import io.github.csaf.validation.requirements.Requirement19
import io.github.csaf.validation.requirements.Requirement20
import io.github.csaf.validation.requirements.Requirement21
import io.github.csaf.validation.requirements.Requirement22
import io.github.csaf.validation.requirements.Requirement23
import io.github.csaf.validation.requirements.Requirement5
import io.github.csaf.validation.requirements.Requirement6
import io.github.csaf.validation.requirements.Requirement7
import io.github.csaf.validation.requirements.Requirement8
import io.github.csaf.validation.requirements.Requirement9
import io.github.csaf.validation.requirements.TlpWhiteAccessible
import io.github.csaf.validation.requirements.UsageOfTls
import io.github.csaf.validation.requirements.ValidCSAFDocument
import io.github.csaf.validation.requirements.ValidFilename
import io.github.csaf.validation.requirements.YearInFolder

/**
 * The "CSAF publisher" role. See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#721-role-csaf-publisher.
 */
open class CSAFPublisherRole : Role {

    override val roleRequirements = none()

    override val documentRequirements =
        allOf(ValidCSAFDocument, ValidFilename, UsageOfTls, TlpWhiteAccessible)
}

/**
 * The "CSAF provider" role. See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#722-role-csaf-provider.
 */
open class CSAFProviderRole : CSAFPublisherRole() {
    override val roleRequirements: Requirement
        get() =
            super.roleRequirements +
                allOf(Requirement6, Requirement7) +
                oneOf(Requirement8, Requirement9, Requirement10) +
                (allOf(YearInFolder, Requirement12, Requirement13, Requirement14) or
                    allOf(Requirement15, Requirement16, Requirement17))

    override val documentRequirements = super.documentRequirements + Requirement5
}

/**
 * The "CSAF trusted provider role".
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#723-role-csaf-trusted-provider.
 */
class CSAFTrustedProviderRole : CSAFProviderRole() {
    override val roleRequirements: Requirement
        get() = super.roleRequirements + Requirement20

    override val documentRequirements =
        super.documentRequirements + allOf(Requirement18, Requirement19)
}

/**
 * The "CSAF lister role". See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#724-role-csaf-lister.
 */
open class CSAFListerRole : Role {
    override var roleRequirements: Requirement = allOf(Requirement6, Requirement21, Requirement22)

    override val documentRequirements = none()
}

/**
 * The "CSAF aggregator role". See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#725-role-csaf-aggregator.
 */
class CSAFAggregatorRole : CSAFListerRole() {
    override var roleRequirements: Requirement = super.roleRequirements + Requirement23

    override val documentRequirements =
        allOf(
            ValidCSAFDocument,
            ValidFilename,
            UsageOfTls,
            TlpWhiteAccessible,
            Requirement5,
        )
}
