import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("buildlogic.kotlin-library-conventions")
}

tasks.withType<KotlinCompile> {
    dependsOn(rootProject.tasks.getByName("generate"))
}

sourceSets.main {
    java.srcDirs("../build/generated-sources/kotlin")
}
