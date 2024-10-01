import org.jetbrains.dokka.gradle.DokkaTask

plugins {
    id("org.jetbrains.dokka")
    signing
    `maven-publish`
}

// Javadoc is mandatory on maven central
val dokkaHtml by tasks.getting(DokkaTask::class)
val javadocJar by tasks.registering(Jar::class) {
    dependsOn(dokkaHtml)
    archiveClassifier.set("javadoc")
    from(dokkaHtml.outputDirectory)
}

// Publication settings for maven central
publishing {
    publications {
        create<MavenPublication>(name) {
            artifact(javadocJar)
            from(components["java"])

            pom {
                url.set("https://github.com/csaf-sbom/kotlin-csaf")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("oxisto")
                        organization.set("Kotlin CSAF Authors")
                        organizationUrl.set("https://github.com/csaf-sbom/kotlin-csaf")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com:csaf-sbom/kotlin-csaf.git")
                    developerConnection.set("scm:git:ssh://github.com:csaf-sbom/kotlin-csaf.git")
                    url.set("https://github.com/csaf-sbom/kotlin-csaf")
                }
            }
        }
    }
}

// Module metadata is not compatible with maven central -> disable
tasks.withType<GenerateModuleMetadata> {
    enabled = false
}

// Configure signing
signing {
    val signingKey: String? by project
    val signingPassword: String? by project

    useInMemoryPgpKeys(signingKey, signingPassword)

    setRequired({
        gradle.taskGraph.hasTask("publish")
    })

    sign(publishing.publications[name])
}
