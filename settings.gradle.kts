plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}
rootProject.name = "kotlin-csaf-library"
include("csaf-schema-codegen", "csaf-import")