plugins {
    id("buildlogic.kotlin-common-conventions")
}

dependencies {
    // This merges all our individual kover results into the root project
    kover(project(":csaf-schema-codegen"))
    kover(project(":csaf-import"))
}

// Create and register ExecutionService which enforces serial execution of assigned tasks.
abstract class SerialExecutionService : BuildService<BuildServiceParameters.None>
val serialExecutionService =
    gradle.sharedServices.registerIfAbsent("serialExecution", SerialExecutionService::class.java) {
        this.maxParallelUsages.set(1)
    }
