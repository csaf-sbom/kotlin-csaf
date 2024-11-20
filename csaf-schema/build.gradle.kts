import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegen
import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegenTask
import org.gradle.kotlin.dsl.kotlin
import org.gradle.kotlin.dsl.sourceSets
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

configure<JSONSchemaCodegen> {
    configFile.set(file("src/jvmMain/resources/codegen-config.json"))
    inputs {
        inputFile(file("src/jvmMain/resources/schema"))
    }
    outputDir.set(file("build/generated-sources/kotlin"))
}

// Configure gradle caching manually for json-kotlin-gradle, as the plugin seems to lack support for it.
var generateTasks = tasks.withType(JSONSchemaCodegenTask::class) {
    inputs.file("src/jvmMain/resources/codegen-config.json").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir("src/jvmMain/resources/schema").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir("build/generated-sources/kotlin")
}

var jarTasks = tasks.withType<Jar>()
jarTasks.forEach {
    it.dependsOn(generateTasks)
}

val dokkaHtml by tasks.getting(DokkaTask::class)
dokkaHtml.dependsOn(generateTasks)
