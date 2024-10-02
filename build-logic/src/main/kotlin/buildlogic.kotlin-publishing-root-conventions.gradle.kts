plugins {
    id("io.github.gradle-nexus.publish-plugin")
}

// Nexus plugin for maven central
nexusPublishing {
    repositories {
        sonatype() {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}
