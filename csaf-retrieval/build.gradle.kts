plugins {
    id("buildlogic.kotlin-library-conventions")
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - Retrieval Module")
        description.set("Retrieval functionality for CSAF in Kotlin")
    }
}

dependencies {
    api(project(":csaf-schema"))
    implementation(project(":csaf-validation"))
    implementation(libs.kotlinx.coroutines)
    implementation(libs.kotlinx.json)
    implementation(libs.bundles.ktor.client)
    implementation(libs.ktor.kotlinx.json)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.ktor.client.mock)
    testImplementation(testFixtures(project(":csaf-validation")))
}
