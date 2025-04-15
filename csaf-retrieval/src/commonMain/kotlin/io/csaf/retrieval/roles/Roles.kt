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
package io.csaf.retrieval.roles

import io.csaf.retrieval.requirements.Requirement
import io.csaf.retrieval.requirements.Requirement11YearInFolder
import io.csaf.retrieval.requirements.Requirement12
import io.csaf.retrieval.requirements.Requirement13
import io.csaf.retrieval.requirements.Requirement14
import io.csaf.retrieval.requirements.Requirement15
import io.csaf.retrieval.requirements.Requirement16
import io.csaf.retrieval.requirements.Requirement17
import io.csaf.retrieval.requirements.Requirement18
import io.csaf.retrieval.requirements.Requirement19
import io.csaf.retrieval.requirements.Requirement1ValidCSAFDocument
import io.csaf.retrieval.requirements.Requirement20
import io.csaf.retrieval.requirements.Requirement21
import io.csaf.retrieval.requirements.Requirement22
import io.csaf.retrieval.requirements.Requirement23
import io.csaf.retrieval.requirements.Requirement2ValidFilename
import io.csaf.retrieval.requirements.Requirement3UsageOfTls
import io.csaf.retrieval.requirements.Requirement4TlpWhiteAccessible
import io.csaf.retrieval.requirements.Requirement5
import io.csaf.retrieval.requirements.Requirement6
import io.csaf.retrieval.requirements.Requirement7
import io.csaf.retrieval.requirements.allOf
import io.csaf.retrieval.requirements.none
import io.csaf.retrieval.requirements.or
import io.csaf.retrieval.requirements.plus

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
            Requirement4TlpWhiteAccessible,
        )
}

/**
 * The "CSAF provider" role. See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#722-role-csaf-provider.
 *
 * Requirements 8, 9 and 10 need to be implicitly fulfilled by the domain-based fetching algorithm.
 * They are therefore not explicitly checked. For reference, see these links:
 * [Requirement 8: security.txt](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#718-requirement-8-securitytxt)
 * [Requirement 9: Well-known
 * URL](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#719-requirement-9-well-known-url-for-provider-metadatajson)
 * [Requirement 10: DNS path](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7110-requirement-10-dns-path)
 */
object CSAFProviderRole : Role {
    override val roleRequirements =
        CSAFPublisherRole.roleRequirements +
            allOf(Requirement6, Requirement7) +
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
            Requirement18,
            Requirement19,
        )
}
