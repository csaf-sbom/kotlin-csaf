pluginManagement {
    // Include 'plugins build' to define convention plugins.
    includeBuild("build-logic")
    repositories {
        gradlePluginPortal()
        maven { url = uri("https://jitpack.io") }
    }
}

plugins {
    // Apply the foojay-resolver plugin to allow automatic download of JDKs
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
    id("org.jetbrains.kotlinx.kover.aggregation") version "0.8.3"
}

kover {
    enableCoverage()

    reports {
        // Ignore generated code
        excludedClasses.add("io.github.csaf.sbom.schema.generated.*")

        // Ignore main classes, since they are for demo only - might be removed in the future
        excludedClasses.add("io.github.csaf.sbom.retrieval.Main*")
        excludedClasses.add("io.github.csaf.sbom.validation.Main*")
    }
}


rootProject.name = "kotlin-csaf"
include("csaf-schema", "csaf-retrieval", "csaf-validation", "csaf-cvss")
