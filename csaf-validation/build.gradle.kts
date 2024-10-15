plugins {
    id("buildlogic.kotlin-library-conventions")
    application
}

application {
    mainClass = "io.github.csaf.sbom.validation.MainKt"
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - Validation Module")
        description.set("Validation support for Kotlin CSAF")
    }
}

dependencies {
    implementation(project(":csaf-schema"))
    implementation(libs.ktor.client.core)
    testImplementation(libs.bundles.ktor.client)
    testImplementation(libs.ktor.client.mock)
}