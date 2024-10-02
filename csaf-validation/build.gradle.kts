plugins {
    id("buildlogic.kotlin-library-conventions")
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - Validation Module")
        description.set("Validation support for Kotlin CSAF")
    }
}

dependencies {
    implementation(project(":csaf-schema"))
}