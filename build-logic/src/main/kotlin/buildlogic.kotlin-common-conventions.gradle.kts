@file:OptIn(ExperimentalKotlinGradlePluginApi::class, ExperimentalWasmDsl::class)

import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    kotlin("multiplatform")

    // Apply formatting conventions
    id("buildlogic.kotlin-formatting-conventions")
}

group = "io.csaf"

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

// Apply a specific Java toolchain to ease working on different environments.
kotlin {
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
        jvmToolchain(21)
    }
    jvm {
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    /*wasmJs {
        browser()
    }*/

    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

// Ensure Java sources are compiled with UTF-8 encoding
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

// The Kotlin Gradle plugin pins Bouncy Castle to a vulnerable 1.80.x range in this internal configuration.
// Force the fixed version (>= 1.85). Even the latest Kotlin release 2.4.21 only pulls in 1.84, so this override is
// still needed; re-check when a newer Kotlin version ships and remove it once Kotlin itself uses Bouncy Castle >= 1.85.
configurations.matching { it.name == "kotlinBouncyCastleConfiguration" }.configureEach {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.bouncycastle") {
            useVersion("1.85")
        }
    }
}
