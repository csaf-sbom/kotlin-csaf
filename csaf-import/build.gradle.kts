plugins {
    id("buildlogic.kotlin-library-conventions")
}

publishing {
    publications {
        named<MavenPublication>("csaf-import") {
            pom {
                artifactId = "csaf-import"
                name.set("Kotlin CSAF - Import Module")
                description.set("Import functionality for CSAF in Kotlin")
            }
        }
    }
}

dependencies {
    api(project(":csaf-schema"))
    implementation(libs.kotlinx.coroutines)
    implementation(libs.kotlinx.json)
    implementation(libs.bundles.ktor.client)
    implementation(libs.ktor.kotlinx.json)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.ktor.client.mock)
}
