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
package io.github.csaf.validation.requirements

import io.github.csaf.sbom.generated.Csaf
import io.github.csaf.sbom.generated.Csaf.Label
import io.github.csaf.validation.*
import io.ktor.client.request.HttpRequest
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.request
import io.ktor.http.URLProtocol

/**
 * Represents Requirement 1: Valid CSAF document.
 *
 * See
 * https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#711-requirement-1-valid-csaf-document
 */
object ValidCSAFDocument : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

/**
 * Represents Requirement 2: Filename
 *
 * See https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#712-requirement-2-filename
 */
object ValidFilename : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

/**
 * Represents Requirement 3: TLS
 *
 * See https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#713-requirement-3-tls
 *
 * We make use of the [HttpResponse] / [HttpRequest] to check the [URLProtocol] for HTTPS.
 */
object UsageOfTls : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO(oxisto): This will also fail if the httpResponse is empty, which is BAD
        return if (ctx.httpResponse?.call?.request?.url?.protocol == URLProtocol.HTTPS) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("JSON was not retrieved via HTTPS"))
        }
    }
}

/**
 * Represents Requirement 4: TLP:WHITE
 *
 * See https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#714-requirement-4-tlpwhite
 *
 * We make use of the [HttpResponse] / [HttpRequest] to check for a "good" status code and check for
 * the (non)-existence of authorization headers in the request.
 */
object TlpWhiteAccessible : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // If we do not have a response, we can assume that its not accessible and we fail
        var response = ctx.httpResponse
        if (response == null) {
            return ValidationFailed(listOf("Response is null"))
        }

        // Only applicable to Csaf document, because all the others do not have a TLP
        var json = ctx.validatable?.json as? Csaf
        if (json == null) {
            return ValidationNotApplicable
        }

        // Only for TLP:WHITE
        if (json.document.distribution?.tlp?.label != Label.WHITE) {
            return ValidationNotApplicable
        }

        // We assume that it is freely accessible, if
        // - We actually got a "ok" error code
        // - We did not send any authorization headers in the request
        if (
            response.status.value in 200..299 && !response.request.headers.contains("Authorization")
        ) {
            return ValidationSuccessful
        }

        // Otherwise, we fail
        return ValidationFailed(listOf("TLP:WHITE document is not freely accessible"))
    }
}

object Requirement5 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement6 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement7 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement8 : Requirement {
    override fun check(ctx: ValidationContext<*, *>) =
        if (ctx.dataSource == ValidationContext.DataSource.SECURITY_TXT) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Not resolved via security.txt"))
        }
}

object Requirement9 : Requirement {
    override fun check(ctx: ValidationContext<*, *>) =
        if (ctx.dataSource == ValidationContext.DataSource.WELL_KNOWN) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Not resolved via .well-known"))
        }
}

object Requirement10 : Requirement {
    override fun check(ctx: ValidationContext<*, *>) =
        if (ctx.dataSource == ValidationContext.DataSource.DNS) {
            ValidationSuccessful
        } else {
            ValidationFailed(listOf("Not resolved via CSAF domain (csaf.data.security.domain.tld)"))
        }
}

object Requirement11 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement12 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement13 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement14 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement15 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement16 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement17 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement18 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement19 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement20 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement21 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement22 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}

object Requirement23 : Requirement {
    override fun check(ctx: ValidationContext<*, *>): ValidationResult {
        // TODO: actually implement the requirement
        return ValidationSuccessful
    }
}
