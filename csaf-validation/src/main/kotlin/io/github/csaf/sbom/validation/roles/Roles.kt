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
package io.github.csaf.sbom.validation.roles

import io.github.csaf.sbom.validation.Requirement
import io.github.csaf.sbom.validation.Role
import io.github.csaf.sbom.validation.allOf
import io.github.csaf.sbom.validation.none
import io.github.csaf.sbom.validation.oneOf
import io.github.csaf.sbom.validation.or
import io.github.csaf.sbom.validation.plus
import io.github.csaf.sbom.validation.requirements.Requirement10
import io.github.csaf.sbom.validation.requirements.Requirement11YearInFolder
import io.github.csaf.sbom.validation.requirements.Requirement12
import io.github.csaf.sbom.validation.requirements.Requirement13
import io.github.csaf.sbom.validation.requirements.Requirement14
import io.github.csaf.sbom.validation.requirements.Requirement15
import io.github.csaf.sbom.validation.requirements.Requirement16
import io.github.csaf.sbom.validation.requirements.Requirement17
import io.github.csaf.sbom.validation.requirements.Requirement18
import io.github.csaf.sbom.validation.requirements.Requirement19
import io.github.csaf.sbom.validation.requirements.Requirement1ValidCSAFDocument
import io.github.csaf.sbom.validation.requirements.Requirement20
import io.github.csaf.sbom.validation.requirements.Requirement21
import io.github.csaf.sbom.validation.requirements.Requirement22
import io.github.csaf.sbom.validation.requirements.Requirement23
import io.github.csaf.sbom.validation.requirements.Requirement2ValidFilename
import io.github.csaf.sbom.validation.requirements.Requirement3UsageOfTls
import io.github.csaf.sbom.validation.requirements.Requirement4TlpWhiteAccessible
import io.github.csaf.sbom.validation.requirements.Requirement5
import io.github.csaf.sbom.validation.requirements.Requirement6
import io.github.csaf.sbom.validation.requirements.Requirement7
import io.github.csaf.sbom.validation.requirements.Requirement8
import io.github.csaf.sbom.validation.requirements.Requirement9

/**
 * The "CSAF publisher" role. See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#721-role-csaf-publisher.
 */
object CSAFPublisherRole : Role {

    override val roleRequirements = none()

    override val documentRequirements =
        allOf(
            Requirement1ValidCSAFDocument,
            Requirement2ValidFilename,
            Requirement3UsageOfTls,
            Requirement4TlpWhiteAccessible
        )
}

/**
 * The "CSAF provider" role. See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#722-role-csaf-provider.
 */
object CSAFProviderRole : Role {
    override val roleRequirements =
        CSAFPublisherRole.roleRequirements +
            allOf(Requirement6, Requirement7) +
            oneOf(Requirement8, Requirement9, Requirement10) +
            (allOf(Requirement11YearInFolder, Requirement12, Requirement13, Requirement14) or
                allOf(Requirement15, Requirement16, Requirement17))

    override val documentRequirements = CSAFPublisherRole.documentRequirements + Requirement5
}

/**
 * The "CSAF trusted provider role".
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#723-role-csaf-trusted-provider.
 */
object CSAFTrustedProviderRole : Role {
    override val roleRequirements = CSAFProviderRole.roleRequirements + Requirement20

    override val documentRequirements =
        CSAFProviderRole.documentRequirements + allOf(Requirement18, Requirement19)
}

/**
 * The "CSAF lister role". See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#724-role-csaf-lister.
 */
object CSAFListerRole : Role {
    override val roleRequirements: Requirement = allOf(Requirement6, Requirement21, Requirement22)

    override val documentRequirements = none()
}

/**
 * The "CSAF aggregator role". See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#725-role-csaf-aggregator.
 */
object CSAFAggregatorRole : Role {
    override val roleRequirements: Requirement = CSAFListerRole.roleRequirements + Requirement23

    override val documentRequirements =
        allOf(
            Requirement1ValidCSAFDocument,
            Requirement2ValidFilename,
            Requirement3UsageOfTls,
            Requirement4TlpWhiteAccessible,
            Requirement5,
        )
}
