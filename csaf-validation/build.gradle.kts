plugins {
    id("buildlogic.kotlin-library-conventions")
    `java-test-fixtures`
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
    implementation(project(":csaf-cvss"))
    testFixturesImplementation(project(":csaf-schema"))
    implementation(libs.ktor.client.core)
    implementation("net.swiftzer.semver:semver:2.0.0")
    testImplementation(libs.bundles.ktor.client)
    testImplementation(libs.ktor.client.mock)

}