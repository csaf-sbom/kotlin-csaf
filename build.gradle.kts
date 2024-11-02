plugins {
    id("buildlogic.kotlin-common-conventions")
    id("buildlogic.kotlin-publishing-root-conventions")
}

// Create and register ExecutionService which enforces serial execution of assigned tasks.
abstract class SerialExecutionService : BuildService<BuildServiceParameters.None>
val serialExecutionService =
    gradle.sharedServices.registerIfAbsent("serialExecution", SerialExecutionService::class.java) {
        this.maxParallelUsages.set(1)
    }
