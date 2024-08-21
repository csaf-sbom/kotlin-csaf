import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegen
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
            exclude("net.pwall.json", "json-kotlin-schema")
            exclude("net.pwall.json", "json-kotlin-schema-codegen")
        }
    }
}

plugins {
    id("buildlogic.kotlin-library-conventions")
}

apply<JSONSchemaCodegenPlugin>()

configure<JSONSchemaCodegen> {
    configFile.set(file("src/main/resources/codegen-config.json"))
    inputs {
        inputFile(file("src/main/resources/schema"))
    }
    outputDir.set(file("src/generated-sources/kotlin"))
}

// Configure gradle caching manually for json-kotlin-gradle, as the plugin seems to lack support for it.
tasks.withType(JSONSchemaCodegenTask::class) {
    inputs.file("src/main/resources/codegen-config.json").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir("src/main/resources/schema").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir("src/generated-sources/kotlin")
}

sourceSets.main {
    kotlin.srcDirs("src/generated-sources/kotlin")
}
