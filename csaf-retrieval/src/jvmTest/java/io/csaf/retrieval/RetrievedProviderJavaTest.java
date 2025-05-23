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
package io.csaf.retrieval;

import io.csaf.validation.ValidationException;
import io.ktor.client.plugins.ResponseException;
import io.ktor.http.HttpStatusCode;
import kotlinx.datetime.Instant;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutionException;

import static io.csaf.retrieval.RetrievedProvider.DEFAULT_CHANNEL_CAPACITY;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the functionality of <code>RetrievedProvider</code> in Java.
 */
public class RetrievedProviderJavaTest {
    private static CsafLoader loader;

    public RetrievedProviderJavaTest() {
        loader = new CsafLoader(TestUtilsKt.mockEngine());
        //noinspection KotlinInternalInJava
        CsafLoader.Companion.setDefaultLoaderFactory$csaf_retrieval(() -> loader);
    }

    @Test
    public void testFromUrlAsync() throws InterruptedException, ExecutionException {
        final var providerByDomain = RetrievedProvider.fromDomainAsync("example.com").get().toString();
        final var providerByUrl = RetrievedProvider.fromUrlAsync(
                "https://example.com/.well-known/csaf/provider-metadata.json"
        ).get().toString();
        assertEquals(providerByDomain, providerByUrl, "Retrieved providers via domain and URL should be equal");
    }

    @Test
    public void testFromAsync() throws InterruptedException, ExecutionException {
        final var provider = RetrievedProvider.fromDomainAsync("example.com").get();
        final var providerExplicit = RetrievedProvider.fromDomainAsync("example.com", loader).get();
        final var expectedDocumentCount = provider.countExpectedDocumentsBlocking();
        assertEquals(
                3,
                expectedDocumentCount,
                "Expected a count of 3 available documents"
        );
        final var documentResults = provider.streamDocuments().toList();
        final var distantPast = Instant.Companion.getDISTANT_PAST();
        final var documentResultsExplicit = providerExplicit.streamDocuments(
                distantPast,
                loader,
                DEFAULT_CHANNEL_CAPACITY
        ).toList();
        final var documentResultsExplicitSlow = providerExplicit.streamDocuments(
                distantPast,
                loader,
                1
        ).toList();
        assertEquals(
                4,
                documentResults.size(),
                "Expected exactly 4 results: One document, two document errors, one index error"
        );
        assertEquals(
                documentResults.size(),
                documentResultsExplicit.size(),
                "Expected same number of result from all overloads"
        );
        assertEquals(
                documentResults.size(),
                documentResultsExplicitSlow.size(),
                "Expected same number of result from all overloads"
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
        final var documentFetchError = (ResponseException) documentError2.getCause();
        assertNotNull(documentFetchError);
        assertEquals(
                HttpStatusCode.Companion.getNotFound(),
                documentFetchError.getResponse().getStatus(),
                "Expected HTTP 404 Not Found"
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
