import com.google.protobuf.gradle.*

plugins {
    java
    alias(libs.plugins.protobuf)
    id("buildlogic.kotlin-library-conventions")
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - Matching Module")
        description.set("Matching functionality for CSAF/ProtoBOM in Kotlin")
    }
}

// Needed for google/protobuf/timestamp.proto
dependencies {
    protobuf(libs.protobuf.java)
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:${libs.versions.protobuf.get()}"
    }
    plugins {
        id("pbandk") {
            artifact = "pro.streem.pbandk:protoc-gen-pbandk-jvm:${libs.versions.pbandk.get()}:jvm8@jar"
        }
    }
    generateProtoTasks {
        ofSourceSet("main").forEach { task ->
            task.builtins {
                remove("java")
            }
            task.plugins {
                id("pbandk") {
                    // Publish the code generated by pbandk as part of the `:protobuf-codegen` project's
                    // `commonMain` source set. This allows other Kotlin Multiplatform subprojects to consume the
                    // pbandk-generated Kotlin code using a regular gradle project dependency.
                    val outputDir = task.getOutputDir(this)
                    project.kotlin.sourceSets.commonMain.configure {
                        // `builtBy` ensures that gradle will automatically run the `generateProto` task before trying
                        // to compile the generated Kotlin code
                        kotlin.srcDir(project.files(outputDir).builtBy(task))
                    }
                }
            }
        }
    }
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(project(":csaf-schema"))
                api(project(":csaf-validation"))
                implementation(libs.pbandk.runtime)
                implementation(libs.ktor.client.core)
                implementation(libs.ktor.client.content.negotiation)
                implementation(libs.ktor.kotlinx.json)
                implementation(libs.kotlinx.coroutines)
                implementation(libs.kotlinx.json)
                implementation(libs.kotlin.logging)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
                implementation(libs.ktor.client.mock)
                implementation(libs.mockk)
            }
        }
    }
}
