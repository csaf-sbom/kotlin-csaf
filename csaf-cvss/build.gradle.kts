plugins {
    id("buildlogic.kotlin-library-conventions")
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - CVSS Module")
        description.set("CVSS calculation utilities for Kotlin CSAF. This is the last release using the io.github.csaf-sbom namespace. Please use io.csaf instead.")
    }
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":csaf-schema"))
        }
    }
}