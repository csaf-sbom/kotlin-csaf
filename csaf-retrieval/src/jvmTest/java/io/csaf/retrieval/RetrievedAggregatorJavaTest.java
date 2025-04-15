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

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the functionality of <code>{@link RetrievedAggregator}</code> in Java.
 */
public class RetrievedAggregatorJavaTest {
    private static CsafLoader loader;

    public RetrievedAggregatorJavaTest() {
        loader = new CsafLoader(TestUtilsKt.mockEngine());
        //noinspection KotlinInternalInJava
        CsafLoader.Companion.setDefaultLoaderFactory$csaf_retrieval(() -> loader);
    }

    @Test
    public void testFetchProvidersAsync() throws ExecutionException, InterruptedException {
        final RetrievedAggregator aggregator =
                RetrievedAggregator.fromUrlAsync("https://example.com/example-01-aggregator.json").get();
        CompletableFuture<List<ResultCompat<RetrievedProvider>>> providersFuture = aggregator.fetchProvidersAsync();
        assertNotNull(providersFuture);
        List<ResultCompat<RetrievedProvider>> providers = providersFuture.get();
        assertNotNull(providers);
        assertFalse(providers.isEmpty(), "Providers list should not be empty");
    }

    @Test
    public void testFetchPublishersAsync() throws ExecutionException, InterruptedException {
        final RetrievedAggregator aggregator =
                RetrievedAggregator.fromUrlAsync("https://example.com/example-01-aggregator.json").get();
        CompletableFuture<List<ResultCompat<RetrievedProvider>>> publishersFuture = aggregator.fetchPublishersAsync();
        assertNotNull(publishersFuture);
        List<ResultCompat<RetrievedProvider>> publishers = publishersFuture.get();
        assertNotNull(publishers);
        assertFalse(publishers.isEmpty(), "Publishers list should not be empty for this test data");
    }

    @Test
    public void testFetchAllAsync() throws ExecutionException, InterruptedException {
        final RetrievedAggregator aggregator =
                RetrievedAggregator.fromUrlAsync("https://example.com/example-01-aggregator.json").get();
        CompletableFuture<List<ResultCompat<RetrievedProvider>>> allFuture = aggregator.fetchAllAsync();
        assertNotNull(allFuture);
        List<ResultCompat<RetrievedProvider>> allResults = allFuture.get();
        assertNotNull(allResults);
        assertFalse(allResults.isEmpty(), "Combined result should not be empty");
        long successCount = allResults.stream().filter(ResultCompat::isSuccess).count();
        long failureCount = allResults.size() - successCount;
        assertEquals(2, successCount, "Number of successful results is incorrect");
        assertEquals(2, failureCount, "Number of failed results is incorrect");
    }
}
