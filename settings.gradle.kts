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
}

rootProject.name = "kotlin-csaf"
include("csaf-schema", "csaf-import", "csaf-validation")
