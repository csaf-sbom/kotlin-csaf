plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    kotlin("jvm")

    // Apply formatting conventions
    id("buildlogic.kotlin-formatting-conventions")

    // Apply code coverage plugin
    id("org.jetbrains.kotlinx.kover")
}

group = "io.github.csaf-sbom"

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("reflect"))
}

testing {
    suites {
        // Configure the built-in test suite
        val test by getting(JvmTestSuite::class) {
            useKotlinTest()
        }
    }
}

// Apply a specific Java toolchain to ease working on different environments.
kotlin {
    compilerOptions {
        jvmToolchain(21)
    }
}

kover {
    reports {
        filters {
            excludes {
                annotatedBy("io.github.csaf.sbom.retrieval.KoverIgnore")
                packages("io.github.csaf.sbom.schema.generated")
            }
        }
    }
}
