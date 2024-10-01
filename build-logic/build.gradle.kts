plugins {
    // Support convention plugins written in Kotlin. Convention plugins are build scripts in 'src/main' that automatically become available as plugins in the main build.
    `kotlin-dsl`
}

repositories {
    // Use the plugin portal to apply community plugins in convention plugins.
    gradlePluginPortal()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation(libs.kotlin.gradle)
    implementation(libs.dokka.gradle)
    implementation(libs.nexus.publish.gradle)
    implementation(libs.kotlin.serialization)
    implementation(libs.spotless.gradle)
    implementation(libs.kover.gradle)
    implementation(libs.kotlin.json.codegen)
    implementation(libs.kotlin.jvm.blocking.bridge.gradle)
}
