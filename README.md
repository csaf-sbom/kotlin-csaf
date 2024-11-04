# kotlin-csaf

[![Actions Status](https://github.com/csaf-sbom/kotlin-csaf/workflows/build/badge.svg)](https://github.com/csaf-sbom/kotlin-csaf/actions) [![codecov](https://codecov.io/gh/csaf-sbom/kotlin-csaf/graph/badge.svg?token=XGBIJHSLUK)](https://codecov.io/gh/csaf-sbom/kotlin-csaf) 

A kotlin implementation of the CSAF standard. This library is currently being developed. We will continuously update this README file with the progress.

## Getting Started

In order to use or develop this library, Java needs to be installed in your target machine. This project is currently aiming at a minimum required JDK version of 21. Please follow instructions for your operating system how to download and install an appropriate JDK version, through a package manager such as apt or homebrew.

### Use as Dependency

The main use case for this project is for developers who want to integrate support for CSAF in their Java/Kotlin-based project. In order to do so, the following will serve as a quickstart guide.

First, `kotlin-csaf` needs to be added as a dependency in your build system, such as Maven or Gradle. We currently publish artefacts on Maven Central under the namespace `io.github.csaf-sbom`, so they can be easily specified as a dependency, for example in Gradle using the Kotlin syntax:

```Kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementation("io.github.csaf-sbom:csaf-schema:0.0.1")
    implementation("io.github.csaf-sbom:csaf-import:0.0.1")
    implementation("io.github.csaf-sbom:csaf-validation:0.0.1")
}
```

The project itself is split into three modules, which can be (more or less) imported independently:

* `csaf-import` contains the logic to retrieve CSAF documents from a provider
* `csaf-schema` contains generated types to represent the CSAF schemas (document, provider, aggregator)
* `csaf-validation` contains the logic needed to validate CSAF documents according to a role, e.g., trusted provider

### Use the Retrieval API

Once the dependency has been imported, one of the first things to try out would be to import/fetch CSAF documents from a provider using a domain. The following code snippet illustrates some key concepts:

```Kotlin
    runBlocking {
    // Create a new "RetrievedProvider" from a domain. This will automatically discover a
    // suitable provider-metadata.json
    RetrievedProvider.from(args[0])
        .onSuccess { provider ->
            println("Discovered provider-metadata.json @ ${provider.json.canonical_url}")
            // Retrieve all documents from all feeds. Note: we currently only support index.txt
            for (result in provider.fetchDocuments()) {
                result.onSuccess { doc ->
                    // The resulting document is a "Csaf" type, which contains the
                    // representation defined in the JSON schema
                    println("Fetched document with ID ${doc.json.document.tracking.id}")
                }
                result.onFailure { ex ->
                    println("Could not fetch document: ${ex.message}, ${ex.cause}")
                }
            }
        }
        .onFailure {
            println("Could not fetch provider meta from ${args[0]}")
            it.printStackTrace()
        }
}
```

## Development

We welcome all kinds of contributions, just be aware that we are still in the early stage of development and things might move or change very quickly. Especially the API design will be very fluid until we reach a stable 1.0 version.

### Initial Steps

We make heavy use of the CSAF TC repo for test cases and other files. So before starting the development you need to initialize the git submodules
```bash
git submodule update --init
```

### Updating the CWE List

We use the canonical source of CWEs from https://cwe.mitre.org/data/downloads.html and store a minified version of it in the [cwe.json](./csaf-validation/src/main/resources/cwe.json) file. This file needs to be updated whenever a new version of the CWE database comes out. There is a special gradle task to do so:

```bash
./gradlew createJWEJson
git add ./csaf-validation/src/main/resources/cwe.json
git commit -m "Updated CWE database" 
```

Feel free to create a Pull Request based on this new commit.

## Dependencies

The full list of dependencies is automatically populated by Dependabot and Gradle and can be viewed [here](https://github.com/csaf-sbom/kotlin-csaf/network/dependencies).
