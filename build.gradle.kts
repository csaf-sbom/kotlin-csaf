plugins {
    java
    alias(libs.plugins.kotlin.jvm)
    signing
    `maven-publish`
}

// Create and register ExecutionService which enforces serial execution of assigned tasks
abstract class SerialExecutionService : BuildService<BuildServiceParameters.None>
val serialExecutionService =
    gradle.sharedServices.registerIfAbsent("serialExecution", SerialExecutionService::class.java) {
        this.maxParallelUsages.set(1)
    }

allprojects {
    group = "de.fhg.aisec.ids"
    version = "1.0-SNAPSHOT"

    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "kotlin")

    dependencies {
        testImplementation(kotlin("test"))
    }

    tasks.test {
        useJUnitPlatform()
    }

    kotlin {
        jvmToolchain(21)
    }
}