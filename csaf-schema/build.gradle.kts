import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegen
import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegenTask
import org.jetbrains.dokka.gradle.DokkaTask

plugins {
    id("buildlogic.kotlin-library-conventions")
    id("net.pwall.json.json-kotlin")
    kotlin("plugin.serialization")
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - Schema Module")
        description.set("CSAF Schema definitions for Kotlin")
    }
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(libs.kotlinx.json)
                api(libs.kotlinx.datetime)
            }
            kotlin {
                compilerOptions {
                    optIn.add("kotlinx.serialization.ExperimentalSerializationApi")
                }
                srcDirs("build/generated-sources/kotlin")
            }
        }
        commonTest {
            dependencies {
                implementation(libs.mockk)
                implementation(kotlin("reflect"))
            }
        }
    }
}

// Define configuration for each code generation task
data class CodegenConfig(
    val configFile: File,
    val inputDir: File,
    val outputDir: File
)

val codegenConfigs = mapOf(
    "generateCodeFromSchema" to CodegenConfig(
        configFile = file("src/jvmMain/resources/codegen-config.json"),
        inputDir = file("src/jvmMain/resources/schema"),
        outputDir = file("build/generated-sources/kotlin")
    ),
    "generateCodeFromNonStrictSchema" to CodegenConfig(
        configFile = file("src/jvmMain/resources/codegen-non-strict-config.json"),
        inputDir = file("src/jvmMain/resources/schema-non-strict"),
        outputDir = file("build/generated-sources/kotlin")
    )
)

// Disable default JSONSchemaCodegen task
tasks.named("generate") {
    enabled = false
}

// Register additional tasks (skip the first one as it's the default)
var prevTask: JSONSchemaCodegenTask? = null
val generateTasks = codegenConfigs.map { (taskName, config) ->
    tasks.register<JSONSchemaCodegenTask>(taskName) {
        description = "Generate Kotlin code from JSON schema with $taskName configuration"
        group = "code generation"

        doFirst {
            project.configure<JSONSchemaCodegen> {
                configFile.set(config.configFile)
                inputFile.set(config.inputDir)
                outputDir.set(config.outputDir)
            }
        }

        inputs.file(config.configFile).withPathSensitivity(PathSensitivity.RELATIVE)
        inputs.dir(config.inputDir).withPathSensitivity(PathSensitivity.RELATIVE)
        outputs.dir(config.outputDir)

        // Make sure tasks don't run in parallel
        prevTask?.let { mustRunAfter(it) }
        prevTask = this
    }
}

tasks.withType<Jar> {
    dependsOn(generateTasks)
}

tasks.withType<DokkaTask> {
    dependsOn(generateTasks)
}

tasks.named("compileKotlinJvm") {
    dependsOn(generateTasks)
}

tasks.named("jvmSourcesJar") {
    dependsOn(generateTasks)
}
