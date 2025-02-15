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

import static org.junit.jupiter.api.Assertions.*;

class RetrievedDocumentTest {

    @Test
    void successfullyParseValidCsafJson() throws IOException {
        String validJson = new String(Objects.requireNonNull(
                getClass().getClassLoader().getResourceAsStream("example.com/directory/2022/bsi-2022-0001.json")
        ).readAllBytes());
        final var result = RetrievedDocument.Companion.fromJson(validJson, "example.com/directory/2022/bsi-2022-0001.json");
        assertTrue(result.isSuccess(), "Parsing should succeed for valid CSAF JSON");
        assertNotNull(result.getOrNull(), "The RetrievedDocument should not be null");
    }

    @Test
    void failWithInvalidJson() {
        final var invalidJson = "{ \"invalid\": true, }"; // Malformed JSON
        final var result = RetrievedDocument.Companion.fromJson(invalidJson, "not-a-real-file.json");
        assertTrue(result.isFailure(), "Parsing should fail for invalid JSON");
        assertNotNull(result.exceptionOrNull(), "A failure result should contain an exception");
    }

    @Test
    void successfullyParseValidCsafJsonStream() {
        final var validJson = Objects.requireNonNull(
                getClass().getClassLoader().getResourceAsStream("example.com/directory/2022/bsi-2022-0001.json")
        );
        final var result = RetrievedDocument.Companion.fromJson(validJson, "example.com/directory/2022/bsi-2022-0001.json");
        assertTrue(result.isSuccess(), "Parsing should succeed for valid CSAF JSON");
        assertNotNull(result.getOrNull(), "The RetrievedDocument should not be null");
    }

    @Test
    void failWithInvalidJsonStream() {
        final var invalidJson = new ByteArrayInputStream("{ \"invalid\": true, }".getBytes(StandardCharsets.UTF_8));
        final var result = RetrievedDocument.Companion.fromJson(invalidJson, "not-a-real-file.json");
        assertTrue(result.isFailure(), "Parsing should fail for invalid JSON");
        assertNotNull(result.exceptionOrNull(), "A failure result should contain an exception");
    }
}