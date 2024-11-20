plugins {
    // Apply the common convention plugin for shared build configuration between library and application projects.
    id("buildlogic.kotlin-common-conventions")

    // Apply publishing conventions
    id("buildlogic.kotlin-publishing-conventions")

    // Apply the java-library plugin for API and implementation separation.
    //`java-library`
}
