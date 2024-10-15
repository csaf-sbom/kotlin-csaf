/*
 * Copyright (c) 2024, The Authors. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.github.csaf.sbom.retrieval;

import io.github.csaf.sbom.validation.ValidationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the functionality of <code>RetrievedProvider</code> in Java.
 */
public class RetrievedProviderJavaTest {
    @BeforeAll
    public static void setup() {
        //noinspection KotlinInternalInJava
        CsafLoader.Companion.setDefaultLoaderFactory$csaf_import(() -> new CsafLoader(TestUtilsKt.mockEngine()));
    }

    @Test
    public void testRetrievedProviderJava() throws InterruptedException, ExecutionException {
        final var provider = RetrievedProvider.fromAsync("example.com").get();
        final var expectedDocumentCount = provider.countExpectedDocumentsBlocking();
        assertEquals(
                3,
                expectedDocumentCount,
                "Expected 3 documents"
        );
        final var documentResults = provider.streamDocuments().toList();
        assertEquals(
                4,
                documentResults.size(),
                "Expected exactly 4 results: One document, two document errors, one index error"
        );
        // Check some random property on successful document
        final var document = documentResults.getFirst().getOrNull();
        assertNotNull(document);
        assertEquals(
                "Bundesamt für Sicherheit in der Informationstechnik",
                document.getJson().getDocument().getPublisher().getName()
        );
        // Check document validation error
        final var documentError1 = documentResults.get(1).exceptionOrNull();
        assertNotNull(documentError1);
        final var validationException = (ValidationException) documentError1.getCause();
        assertNotNull(validationException);
        assertEquals(
                "Filename \"bsi-2022_2-01.json\" does not match conformance, expected \"bsi-2022-0001.json\"",
                validationException.getErrors().getFirst()
        );
        // Check document error
        final var documentError2 = documentResults.get(2).exceptionOrNull();
        assertNotNull(documentError2);
        final var documentFetchError = (Exception) documentError2.getCause();
        assertNotNull(documentFetchError);
        assertEquals(
                "Could not retrieve https://example.com/directory/2024/does-not-exist.json: Not Found",
                documentFetchError.getMessage()
        );
        // Check index error
        final var indexError = documentResults.get(3).exceptionOrNull();
        assertNotNull(indexError);
        assertEquals(
                "Failed to fetch index.txt from directory at https://example.com/invalid-directory",
                indexError.getMessage()
        );
    }
}
