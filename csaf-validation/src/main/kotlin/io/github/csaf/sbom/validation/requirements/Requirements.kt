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
package io.github.csaf.sbom.validation.requirements

import io.github.csaf.sbom.schema.generated.Csaf
import io.github.csaf.sbom.schema.generated.Csaf.Label
import io.github.csaf.sbom.schema.generated.Provider
import io.github.csaf.sbom.validation.*
import io.ktor.client.request.HttpRequest
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.request
import io.ktor.http.*
import kotlin.io.path.toPath

/**
 * Represents
 * [Requirement 1: Valid CSAF document](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#711-requirement-1-valid-csaf-document).
 */
object Requirement1ValidCSAFDocument : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO(oxisto): We need to get the errors from the CSAF schema somehow :(
        ctx.json ?: return ValidationFailed(listOf("We do not have a valid JSON"))

        // TODO(oxisto): Check for further conformance that are not checked by CSAF schema
        return ValidationSuccessful
    }
}

/**
 * Represents
 * [Requirement 2: Filename](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#712-requirement-2-filename).
 */
object Requirement2ValidFilename : Requirement {
    private val idSanitizerRegex = Regex("[^+\\-a-z0-9]+")

    override fun check(ctx: ValidationContext): ValidationResult {
        // Only applicable for CSAF documents
        val json = ctx.json as? Csaf ?: return ValidationNotApplicable

        // Try to build the filename and then compare it
        val should = json.document.tracking.id.lowercase().replace(idSanitizerRegex, "_") + ".json"

        // Extract filename out of response?
        @Suppress("SimpleRedundantLet")
        val filename = ctx.httpResponse?.let { it.request.url.segments.lastOrNull() }
        return if (filename == should) {
            ValidationSuccessful
        } else {
            ValidationFailed(
                listOf("Filename \"$filename\" does not match conformance, expected \"$should\"")
            )
        }
    }
}

/**
 * Represents
 * [Requirement 3: TLS](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#713-requirement-3-tls).
 *
 * We make use of the [HttpResponse] / [HttpRequest] to check the [URLProtocol] for HTTPS.
 */
object Requirement3UsageOfTls : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        return if (
            ctx.httpResponse?.let { it.request.url.protocol == URLProtocol.HTTPS } != false
        ) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("JSON was not retrieved via HTTPS"))
        }
    }
}

/**
 * Represents
 * [Requirement 4: TLP:WHITE](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#714-requirement-4-tlpwhite).
 *
 * We make use of the [HttpResponse] / [HttpRequest] to check for a "good" status code and check for
 * the (non)-existence of authorization headers in the request.
 */
object Requirement4TlpWhiteAccessible : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // Only applicable to Csaf document, because all the others do not have a TLP
        val json = ctx.json as? Csaf ?: return ValidationNotApplicable

        // Only for TLP:WHITE
        if (json.document.distribution?.tlp?.label != Label.WHITE) {
            return ValidationNotApplicable
        }

        // If we do not have a response, we can assume that it's not accessible and we fail
        val response = ctx.httpResponse ?: return ValidationFailed(listOf("Response is null"))

        // We assume that it is freely accessible, if
        // - We actually got an "OK-ish" error code
        // - We did not send any authorization headers in the request
        if (response.status.isSuccess() && !response.request.headers.contains("Authorization")) {
            return ValidationSuccessful
        }

        // Otherwise, we fail
        return ValidationFailed(listOf("TLP:WHITE document is not freely accessible"))
    }
}

/**
 * Represents
 * [Requirement 5: TLP:AMBER and TLP:RED](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#715-requirement-5-tlpamber-and-tlpred).
 *
 * We make use of the [HttpResponse] / [HttpRequest] to check for a "good" status code and check for
 * the existence of authorization headers in the request or for the non-existence with a "bad"
 * status code.
 */
// TODO: This should be split into a document requirement and a role requirement
object Requirement5TlpAmberRedNotAccessible : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // Only applicable to Csaf document, because all the others do not have a TLP
        val json = ctx.json as? Csaf ?: return ValidationNotApplicable

        // Only for TLP:AMBER and TLP:RED
        if (
            json.document.distribution?.tlp?.label != Label.AMBER ||
                json.document.distribution?.tlp?.label != Label.RED
        ) {
            return ValidationNotApplicable
        }

        // If we do not have a response, we can assume that it's not accessible and we fail
        val response = ctx.httpResponse ?: return ValidationFailed(listOf("Response is null"))

        // We assume that it is access protected, if
        // - We got access denied/permission denied and did not see authorization request headers or
        // - We got a successful status code but did see authorization headers
        return when {
            (response.status == HttpStatusCode.Forbidden ||
                response.status == HttpStatusCode.Unauthorized) &&
                !response.request.headers.contains("Authorization") -> ValidationSuccessful
            response.status.isSuccess() && response.request.headers.contains("Authorization") -> {
                ValidationSuccessful
            }

            // Otherwise, we fail
            else -> ValidationFailed(listOf("TLP:WHITE document is not freely accessible"))
        }
    }
}

object Requirement5TlpAmberRedNotListedWithWhite : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // Only applicable to the provider
        val json = ctx.json as? Provider ?: return ValidationNotApplicable

        // We can only check for that ROLIE feeds, because the directory-based ones do not have
        // labels. First, gather all RED/AMBER feeds.
        var redAmberFeeds =
            json.distributions
                ?.flatMap { it.rolie?.feeds ?: listOf() }
                ?.filter {
                    it.tlp_label == Provider.TlpLabel.RED || it.tlp_label == Provider.TlpLabel.AMBER
                } ?: listOf()
        var otherFeeds =
            json.distributions
                ?.flatMap { it.rolie?.feeds ?: listOf() }
                ?.filter {
                    it.tlp_label != Provider.TlpLabel.RED && it.tlp_label != Provider.TlpLabel.AMBER
                } ?: listOf()

        // If we have a feed that contains AMBER or RED, they must not be on the same (base) path as
        // TLP:WHITE.
        for (feed in redAmberFeeds) {
            var basePath = feed.url.toPath().parent
            var otherPaths = otherFeeds.map { it.url.toPath().parent }
            if (basePath in otherPaths) {
                return ValidationFailed(
                    listOf(
                        "Path of ${feed.tlp_label} feed conflicts with path of ${feed.tlp_label} feed: $basePath"
                    )
                )
            }
        }

        // If there is no conflict, we pass
        return ValidationSuccessful
    }
}

object Requirement6 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement7 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

/**
 * Represents
 * [Requirement 8: security.txt](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#718-requirement-8-securitytxt).
 *
 * The check itself is already performed in the retrieval API, we can just check for the existence
 * of the data source here.
 */
object Requirement8SecurityTxt : Requirement {
    override fun check(ctx: ValidationContext) =
        if (ctx.dataSource == ValidationContext.DataSource.SECURITY_TXT) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Not resolved via security.txt"))
        }
}

/**
 * Represents
 * [Requirement 9: Well-known URL](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#719-requirement-9-well-known-url-for-provider-metadatajson).
 *
 * The check itself is already performed in the retrieval API, we can just check for the existence
 * of the data source here.
 */
object Requirement9WellKnownURL : Requirement {
    override fun check(ctx: ValidationContext) =
        if (ctx.dataSource == ValidationContext.DataSource.WELL_KNOWN) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Not resolved via .well-known"))
        }
}

/**
 * Represents
 * [Requirement 10: DNS path](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#7110-requirement-10-dns-path).
 *
 * The check itself is already performed in the retrieval API, we can just check for the existence
 * of the data source here.
 */
object Requirement10DNSPath : Requirement {
    override fun check(ctx: ValidationContext) =
        if (ctx.dataSource == ValidationContext.DataSource.DNS) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Not resolved via CSAF domain (csaf.data.security.domain.tld)"))
        }
}

// TODO(oxisto): This is actually a document requirement, but it is part of an OR clause in the role
//  requirement :(
object Requirement11YearInFolder : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement12 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement13 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement14 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement15 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement16 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement17 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement18 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement19 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement20 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement21 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement22 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement23 : Requirement {
    override fun check(ctx: ValidationContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}
