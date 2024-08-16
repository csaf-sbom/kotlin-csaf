# kotlin-csaf

[![Actions Status](https://github.com/csaf-sbom/kotlin-csaf/workflows/build/badge.svg)](https://github.com/csaf-sbom/kotlin-csaf/actions) [![codecov](https://codecov.io/gh/csaf-sbom/kotlin-csaf/graph/badge.svg?token=XGBIJHSLUK)](https://codecov.io/gh/csaf-sbom/kotlin-csaf) 

A kotlin implementation of the CSAF standard. This library is currently being developed. We will continuously update this README file with the progress.

## Requirements

The root level of this project features the `generate` task which creates Kotlin Pojos from CSAF JSON Schema files.

In order to work correctly, it requires our patched versions of `json-kotlin-schema` and `json-kotlin-schema-codegen`
to be available in the local Maven repository (i.e. `~/.m2`).

To deploy that libraries locally, checkout the following two git projects and run `mvn install` inside both of them:
- https://github.com/csaf-sbom/json-kotlin-schema
- https://github.com/csaf-sbom/json-kotlin-schema-codegen

If Apache Maven is not installed on your system yet, follow the instructions of the following site:
https://maven.apache.org/install.html
