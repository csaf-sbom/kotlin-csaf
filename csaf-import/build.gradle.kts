plugins {
    id("buildlogic.kotlin-library-conventions")
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
