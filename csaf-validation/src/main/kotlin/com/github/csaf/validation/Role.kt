package com.github.csaf.validation

/**
 * Represents a CSAF profile according to https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#4-profiles.
 */
abstract class Role {
}

infix fun Requirement.and(other: Requirement): Any {
    return Any()
}

infix fun Requirement.or(other: Requirement): Any {
    return Any()
}