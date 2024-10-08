plugins {
    id("buildlogic.kotlin-common-conventions")
    id("buildlogic.kotlin-publishing-root-conventions")
}

dependencies {
    // This merges all our individual kover results into the root project
    kover(project(":csaf-schema"))
    kover(project(":csaf-import"))
    kover(project(":csaf-validation"))
}

// Create and register ExecutionService which enforces serial execution of assigned tasks.
abstract class SerialExecutionService : BuildService<BuildServiceParameters.None>
val serialExecutionService =
    gradle.sharedServices.registerIfAbsent("serialExecution", SerialExecutionService::class.java) {
        this.maxParallelUsages.set(1)
    }
