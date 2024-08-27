pluginManagement {
    // Include 'plugins build' to define convention plugins.
    includeBuild("build-logic")
    resolutionStrategy {
        eachPlugin {
            if (requested.id.namespace == "net.pwall.json") {
                useModule("com.github.csaf-sbom:json-kotlin-gradle:0.108.2")
            }
        }
    }
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
include("csaf-schema", "csaf-import")
