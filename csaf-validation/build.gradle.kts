plugins {
    id("buildlogic.kotlin-library-conventions")
}

publishing {
    publications {
        named<MavenPublication>("csaf-validation") {
            pom {
                artifactId = "csaf-validation"
                name.set("Kotlin CSAF - Validation Module")
                description.set("Validation support for Kotlin CSAF")
            }
        }
    }
}

dependencies {
    implementation(project(":csaf-schema"))
}
