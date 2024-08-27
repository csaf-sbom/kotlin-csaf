import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegen
import net.pwall.json.kotlin.codegen.gradle.JSONSchemaCodegenTask

plugins {
    id("buildlogic.kotlin-library-conventions")
    id("net.pwall.json.json-kotlin") version "0.108.2"
}

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
