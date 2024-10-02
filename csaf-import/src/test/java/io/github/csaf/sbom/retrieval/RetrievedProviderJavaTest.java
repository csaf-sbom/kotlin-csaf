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

import org.junit.jupiter.api.Test;

import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the functionality of <code>RetrievedProvider</code> in Java.
 */
public class RetrievedProviderJavaTest {
    private static final CsafLoader loader = new CsafLoader(TestUtilsKt.getMockEngine());

    @Test
    public void test() throws InterruptedException, ExecutionException {
        final var provider = RetrievedProvider.fromAsync("example.com", loader).get();
        final var documentResults = provider.fetchDocumentsAsync(loader).get();

        assertEquals(
                3,
                documentResults.size(),
                "Expected exactly 3 results: One document, one document error, one index error"
        );
        // Check some random property on successful document
        final var document = documentResults.getFirst().getOrNull();
        assertNotNull(document);
        assertEquals(
                "Bundesamt für Sicherheit in der Informationstechnik",
                document.getJson().getDocument().getPublisher().getName()
        );
        // Check document error
        final var documentError = documentResults.get(1).exceptionOrNull();
        assertNotNull(documentError);
        assertEquals(
                "Failed to fetch CSAF document from https://www.example.com/directory/2024/does-not-exist.json",
                documentError.getMessage()
        );
        // Check index error
        final var indexError = documentResults.get(2).exceptionOrNull();
        assertNotNull(indexError);
        assertEquals(
                "Failed to fetch index.txt from directory at https://www.example.com/invalid-directory",
                indexError.getMessage()
        );
    }
}
