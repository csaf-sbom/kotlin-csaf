import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.dokka")
    id("com.vanniktech.maven.publish")
}

tasks.whenTaskAdded {
    if (name == "generate") {
        dependsOn(tasks.named("jvmSourcesJar"))
    }
}

// Publication settings for maven central
mavenPublishing {
    configure(KotlinMultiplatform(
        javadocJar = JavadocJar.Dokka("dokkaHtml"),
        sourcesJar = true,
    ))
    coordinates(project.group.toString(), project.name, version.toString())

    pom {
        url.set("https://github.com/csaf-sbom/kotlin-csaf")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
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

    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()
}

// Conditionally disable signing for non-Maven Central publishing tasks (for local test publishing)
gradle.taskGraph.whenReady {
    val isPublishingToMavenCentral = allTasks.any {
        it.name.contains("publishToMavenCentral")
    }

    if (!isPublishingToMavenCentral) {
        allTasks.forEach { task ->
            if (task.name.startsWith("sign")) {
                task.enabled = false
            }
        }
    }
}
