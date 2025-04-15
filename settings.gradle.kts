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
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0"
    id("org.jetbrains.kotlinx.kover.aggregation") version "0.9.1"
}

kover {
    enableCoverage()

    reports {
        // Ignore generated code
        excludedClasses.add("io.csaf.schema.generated.*")
        excludedClasses.add("io.csaf.validation.generated.*")
        excludedClasses.add("io.csaf.validation.tests.CWE*")
        excludedClasses.add("com.google.protobuf.*")
        excludedClasses.add("protobom.protobom.*")

        // Ignore main classes, since they are for demo only - might be removed in the future
        excludedClasses.add("io.csaf.retrieval.demo.*")
        excludedClasses.add("io.csaf.validation.Main*")
    }
}

rootProject.name = "kotlin-csaf"
include("csaf-schema", "csaf-retrieval", "csaf-validation", "csaf-cvss", "csaf-matching")
