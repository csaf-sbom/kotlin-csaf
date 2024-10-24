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
package io.github.csaf.sbom.retrieval

import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class RetrievedAggregatorTest {
    init {
        CsafLoader.defaultLoaderFactory = { CsafLoader(mockEngine()) }
    }

    @Test
    fun testRetrievedAggregator() = runTest {
        val lister = RetrievedAggregator.from("https://example.com/example-01-lister.json")
        assertTrue(lister.isSuccess)
        val aggregator = RetrievedAggregator.from("https://example.com/example-01-aggregator.json")
        assertTrue(aggregator.isSuccess)
        val nonExistingLister =
            RetrievedAggregator.from("https://does-not-exist.com/example-01-lister.json")
        assertTrue(nonExistingLister.isFailure)
    }
}
