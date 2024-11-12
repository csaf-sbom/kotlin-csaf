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
package io.github.csaf.sbom.validation.profiles

/**
 * A profile according to
 * [Section 4](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#4-profiles).
 */
sealed interface Profile {
    /** The expected category string. Can be empty to "allow all" (used for [CSAFBase]). */
    val category: String?
}

/**
 * [Profile 1: CSAF
 * Base](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#41-profile-1-csaf-base).
 */
object CSAFBase : Profile {
    override val category = "csaf_base"
}

/**
 * [Profile 2: Security incident
 * response](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#42-profile-2-security-incident-response).
 */
object SecurityIncidentResponse : Profile {
    override val category = "csaf_security_incident_response"
}

/**
 * [Profile 3: Informational
 * Advisory](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#43-profile-3-informational-advisory).
 */
object InformationalAdvisory : Profile {
    override val category = "csaf_informational_advisory"
}

/**
 * [Profile 4: Security
 * Advisory](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#44-profile-4-security-advisory).
 */
object SecurityAdvisory : Profile {
    override val category = "csaf_security_advisory"
}

/**
 * [Profile 5:
 * VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#45-profile-5-vex).
 */
object VEX : Profile {
    override val category = "csaf_vex"
}

/** List of defined "official" profiles. */
val officialProfiles =
    mapOf<String, Profile>(
        CSAFBase.category to CSAFBase,
        SecurityIncidentResponse.category to SecurityIncidentResponse,
        InformationalAdvisory.category to InformationalAdvisory,
        SecurityAdvisory.category to SecurityAdvisory,
        VEX.category to VEX
    )
