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
import io.github.csaf.sbom.mockEngine
import io.github.csaf.sbom.retrieval.RetrievedProvider
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlinx.coroutines.test.runTest

class RetrievalTest {
    @Test
    fun testRetrievedProviderFrom() {
        runTest {
            val result = RetrievedProvider.from("example.com", engine = mockEngine)
            val provider = result.getOrNull()
            assertNotNull(provider)

            val allDocuments = provider.fetchDocuments()
        }
    }
}
