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

dependencies {
    api(libs.kotlinx.json)
}

configure<JSONSchemaCodegen> {
    configFile.set(file("src/main/resources/codegen-config.json"))
    inputs {
        inputFile(file("src/main/resources/schema"))
    }
    outputDir.set(file("build/generated-sources/kotlin"))
}

// Configure gradle caching manually for json-kotlin-gradle, as the plugin seems to lack support for it.
var generateTasks = tasks.withType(JSONSchemaCodegenTask::class) {
    inputs.file("src/main/resources/codegen-config.json").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir("src/main/resources/schema").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir("build/generated-sources/kotlin")
}

var jarTasks = tasks.withType<Jar>()
jarTasks.forEach {
    it.dependsOn(generateTasks)
}
val dokkaHtml by tasks.getting(DokkaTask::class)
dokkaHtml.dependsOn(generateTasks)

sourceSets.main {
    kotlin.srcDirs("build/generated-sources/kotlin")
}

