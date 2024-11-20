plugins {
    id("buildlogic.kotlin-library-conventions")
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - CVSS Module")
        description.set("CVSS calculation utilities for Kotlin CSAF")
    }
}

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(project(":csaf-schema"))
        }
    }
}