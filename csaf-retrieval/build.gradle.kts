plugins {
    id("buildlogic.kotlin-library-conventions")
}

mavenPublishing {
    pom {
        name.set("Kotlin CSAF - Retrieval Module")
        description.set("Retrieval functionality for CSAF in Kotlin")
    }
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(project(":csaf-schema"))
                api(project(":csaf-validation"))
                implementation(libs.ktor.client.core)
                implementation(libs.ktor.client.content.negotiation)
                implementation(libs.ktor.kotlinx.json)
                implementation(libs.kotlinx.coroutines)
                implementation(libs.kotlinx.json)
                implementation(libs.kotlin.logging)
            }
        }
        jvmMain {
            dependencies {
                implementation(libs.ktor.client.java)
                implementation(libs.bundles.slf4j)
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
