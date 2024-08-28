plugins {
    id("buildlogic.kotlin-library-conventions")
}

dependencies {
    api(project(":csaf-schema"))
    implementation(libs.kotlinx.coroutines)
    implementation(libs.bundles.kjson)
    implementation(libs.bundles.ktor.client)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.ktor.client.mock)
}
