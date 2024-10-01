plugins {
    id("io.github.gradle-nexus.publish-plugin")
}

// Nexus plugin for maven central
nexusPublishing {
    repositories {
        sonatype() {
            val mavenCentralUsername: String? by project
            val mavenCentralPassword: String? by project

            username.set(mavenCentralUsername)
            password.set(mavenCentralPassword)
        }
    }
}
