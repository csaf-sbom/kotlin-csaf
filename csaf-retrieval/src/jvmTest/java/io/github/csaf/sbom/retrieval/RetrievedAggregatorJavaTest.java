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

import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    public void testRetrievedAggregatorJava() throws InterruptedException, ExecutionException {
        final var aggregator = RetrievedAggregator.fromAsync("https://example.com/example-01-lister.json").get();
        assertNotNull(aggregator);
    }
}
