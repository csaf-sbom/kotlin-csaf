plugins {
    id("buildlogic.kotlin-common-conventions")
}

dependencies {
    // This merges all our individual kover results into the root project
    kover(project(":csaf-import"))
    kover(project(":csaf-schema-codegen"))
}