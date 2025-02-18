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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.*;

class RetrievedDocumentJavaTest {
    private static CsafLoader loader;

    public RetrievedDocumentJavaTest() {
        loader = new CsafLoader(TestUtilsKt.mockEngine());
        //noinspection KotlinInternalInJava
        CsafLoader.Companion.setDefaultLoaderFactory$csaf_retrieval(() -> loader);
    }

    @Test
    void successfullyParseValidCsafJson() throws IOException {
        final var url = "https://example.com/directory/2022/bsi-2022-0001.json";
        final var validJsonString = new String(Objects.requireNonNull(
                getClass().getClassLoader().getResourceAsStream(url.substring(url.indexOf("//") + 2))
        ).readAllBytes());
        final var result = RetrievedDocument.fromJson(validJsonString, url);
        assertTrue(result.isSuccess(), "Parsing should succeed for valid CSAF JSON");
        assertNotNull(result.getOrNull(), "The RetrievedDocument should not be null");
    }

    @Test
    void failWithInvalidJson() {
        final var invalidJson = "{ \"invalid\": true, }"; // Malformed JSON
        final var result = RetrievedDocument.fromJson(invalidJson, "not-a-real-file.json");
        assertTrue(result.isFailure(), "Parsing should fail for invalid JSON");
        assertNotNull(result.exceptionOrNull(), "A failure result should contain an exception");
    }

    @Test
    void successfullyParseValidCsafJsonStream() {
        final var url = "https://example.com/directory/2022/bsi-2022-0001.json";
        final var validJsonStream = Objects.requireNonNull(
                getClass().getClassLoader().getResourceAsStream(url.substring(url.indexOf("//") + 2))
        );
        final var result = RetrievedDocument.fromJson(validJsonStream, url);
        assertTrue(result.isSuccess(), "Parsing should succeed for valid CSAF JSON");
        assertNotNull(result.getOrNull(), "The RetrievedDocument should not be null");
    }

    @Test
    void failWithInvalidJsonStream() {
        final var invalidJson = new ByteArrayInputStream("{ \"invalid\": true, }".getBytes(StandardCharsets.UTF_8));
        final var result = RetrievedDocument.fromJson(invalidJson, "not-a-real-file.json");
        assertTrue(result.isFailure(), "Parsing should fail for invalid JSON");
        assertNotNull(result.exceptionOrNull(), "A failure result should contain an exception");
    }

    @Test
    void loadDocumentFromUrl() throws ExecutionException, InterruptedException {
        final var url = "https://example.com/directory/2022/bsi-2022-0001.json";
        final var validJsonStream = Objects.requireNonNull(
                getClass().getClassLoader().getResourceAsStream(url.substring(url.indexOf("//") + 2))
        );
        final var resultByStream = RetrievedDocument.fromJson(validJsonStream, url).getOrNull();
        assertNotNull(resultByStream);
        final var resultByUrl = RetrievedDocument.fromUrlAsync(url);
        assertEquals(
                resultByStream.toString(),
                resultByUrl.get().toString(),
                "Retrieved document from stream and URL should be equal"
        );
    }
}