import de.undercouch.gradle.tasks.download.Download
import groovy.json.JsonOutput
import groovy.xml.XmlParser
import org.gradle.kotlin.dsl.invoke

plugins {
    id("buildlogic.kotlin-library-conventions")
    id("de.undercouch.download") version "5.6.0"
    kotlin("plugin.serialization")

    `java-test-fixtures`
    application
}

application {
    mainClass = "io.github.csaf.sbom.validation.MainKt"
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - Validation Module")
        description.set("Validation support for Kotlin CSAF")
    }
}

dependencies {
    implementation(project(":csaf-schema"))
    implementation(project(":csaf-cvss"))
    testFixturesImplementation(project(":csaf-schema"))
    testFixturesImplementation(kotlin("test"))
    implementation(libs.ktor.client.core)
    implementation("net.swiftzer.semver:semver:2.0.0")
    testImplementation(libs.bundles.ktor.client)
    testImplementation(libs.ktor.client.mock)
}

open class IncrementalReverseTask : DefaultTask() {

    @get:Incremental
    @get:InputFile
    val inputFile: RegularFileProperty = project.objects.fileProperty()

    @get:OutputFile
    val outputFile: RegularFileProperty = project.objects.fileProperty()

    @Suppress("UNCHECKED_CAST")
    @TaskAction
    fun execute() {
        val text = inputFile.asFile.get().readText()
        // Read XML file
        val root = XmlParser().parseText(text)
        val list = root.value() as List<groovy.util.Node>
        val weaknessesNode = list[0].value() as List<groovy.util.Node>
        var map = mapOf("weaknesses" to weaknessesNode.map {
            mapOf("id" to "CWE-${it.attribute("ID")}", "name" to it.attribute("Name"))
        })

        outputFile.asFile.get().writeText(JsonOutput.toJson(map))
    }
}

tasks {
    val downloadCWE by registering(Download::class) {
        src("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")
        dest(File(projectDir.resolve("src/main/resources"), "cwec_latest.xml.zip"))
        onlyIfModified(true)
    }

    val unzipCWE by registering(Copy::class) {
        from(zipTree(File(projectDir.resolve("src/main/resources"), "cwec_latest.xml.zip"))) {
            include("*.xml")
            rename { "cwe.xml" }
        }
        into(projectDir.resolve("src/main/resources"))
        dependsOn(downloadCWE)
    }

    val createJWEJson by registering(IncrementalReverseTask::class) {
        inputFile = projectDir.resolve("src/main/resources/cwe.xml")
        outputFile = projectDir.resolve("src/main/resources/cwe.json")
        dependsOn(unzipCWE)
    }
}