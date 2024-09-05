import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegen
import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegenTask

plugins {
    id("buildlogic.kotlin-library-conventions")
    id("net.pwall.json.json-kotlin")
    kotlin("plugin.serialization")
}

dependencies {
    implementation(libs.kotlinx.json)
    testImplementation(libs.mockito.kotlin)
}

configure<JSONSchemaCodegen> {
    configFile.set(file("src/main/resources/codegen-config.json"))
    inputs {
        inputFile(file("src/main/resources/schema"))
    }
    outputDir.set(file("build/generated-sources/kotlin"))
}

// Configure gradle caching manually for json-kotlin-gradle, as the plugin seems to lack support for it.
tasks.withType(JSONSchemaCodegenTask::class) {
    inputs.file("src/main/resources/codegen-config.json").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir("src/main/resources/schema").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir("build/generated-sources/kotlin")
}

sourceSets.main {
    kotlin.srcDirs("build/generated-sources/kotlin")
}
