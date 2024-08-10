plugins {
    id("buildlogic.kotlin-application-conventions")
}

dependencies {
    implementation(libs.codegen)
    implementation(libs.bundles.ktor.client)
}

application {
    // Define the main class for the application.
    mainClass = "com.github.csaf.GeneratorKt"
}