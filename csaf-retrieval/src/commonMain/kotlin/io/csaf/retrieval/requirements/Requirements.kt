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
package io.csaf.retrieval.requirements

import io.csaf.retrieval.RetrievalContext
import io.csaf.schema.generated.Csaf
import io.csaf.schema.generated.Csaf.Label
import io.csaf.validation.*
import io.csaf.validation.tests.mandatoryTests
import io.csaf.validation.tests.test
import io.ktor.client.request.HttpRequest
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.request
import io.ktor.http.*

/**
 * Represents
 * [Requirement 1: Valid CSAF document](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#711-requirement-1-valid-csaf-document).
 */
object Requirement1ValidCSAFDocument : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO(oxisto): We need to get the errors from the CSAF schema somehow :(
        val json =
            ctx.json as? Csaf ?: return ValidationFailed(listOf("We do not have a valid JSON"))

        return mandatoryTests.test(json)
    }
}

/**
 * Represents
 * [Requirement 2: Filename](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#712-requirement-2-filename).
 */
object Requirement2ValidFilename : Requirement {
    private val idSanitizerRegex = Regex("[^+\\-a-z0-9]+")

    override fun check(ctx: RetrievalContext): ValidationResult {
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
    override fun check(ctx: RetrievalContext): ValidationResult {
        val response = ctx.httpResponse ?: return ValidationNotApplicable

        return if (response.request.url.protocol == URLProtocol.HTTPS) {
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
    override fun check(ctx: RetrievalContext): ValidationResult {
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

object Requirement5 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement6 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement7 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

// TODO(oxisto): This is actually a document requirement, but it is part of an OR clause in the role
//  requirement :(
object Requirement11YearInFolder : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement12 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement13 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement14 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement15 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement16 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement17 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement18 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement19 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement20 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement21 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement22 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement23 : Requirement {
    override fun check(ctx: RetrievalContext): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}
