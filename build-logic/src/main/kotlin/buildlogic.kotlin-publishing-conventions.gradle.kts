import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    id("org.jetbrains.dokka")
    signing
    id("com.vanniktech.maven.publish")
}

// Publication settings for maven central
mavenPublishing {
    configure(KotlinJvm(
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
