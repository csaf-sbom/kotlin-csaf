import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegenPlugin
import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegenTask

buildscript {
    repositories {
        maven { url = uri("https://jitpack.io") }
        mavenCentral()
    }
    dependencies {
        // A.t.m. we need our patched version of json-kotlin-schema-codegen here.
        classpath("com.github.csaf-sbom:json-kotlin-schema-codegen:0.108.2")
        classpath("net.pwall.json:json-kotlin-gradle:0.107") {
            exclude("net.pwall.json", "json-kotlin-schema-codegen")
        }
    }
}

plugins {
    id("buildlogic.kotlin-common-conventions")
}

dependencies {
    // This merges all our individual kover results into the root project
    kover(project(":csaf-import"))
}

// Create and register ExecutionService which enforces serial execution of assigned tasks.
abstract class SerialExecutionService : BuildService<BuildServiceParameters.None>
val serialExecutionService =
    gradle.sharedServices.registerIfAbsent("serialExecution", SerialExecutionService::class.java) {
        this.maxParallelUsages.set(1)
    }

apply<JSONSchemaCodegenPlugin>()

// Configure gradle caching manually for json-kotlin-gradle, as the plugin seems to lack support for it.
tasks.withType(JSONSchemaCodegenTask::class) {
    inputs.file("src/main/resources/codegen-config.json").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir("src/main/resources/schema").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir("build/generated-sources/kotlin")
}

allprojects {
    group = "de.fhg.aisec.ids"
    version = "1.0-SNAPSHOT"

    repositories {
        mavenLocal()
        mavenCentral()
    }
}
