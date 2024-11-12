@file:OptIn(ExperimentalKotlinGradlePluginApi::class, ExperimentalWasmDsl::class)

import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    kotlin("multiplatform")

    // Apply formatting conventions
    id("buildlogic.kotlin-formatting-conventions")
}

group = "io.github.csaf-sbom"

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
        withJava()
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

