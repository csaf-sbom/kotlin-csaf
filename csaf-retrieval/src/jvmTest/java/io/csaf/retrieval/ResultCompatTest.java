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

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;


/**
 * This test is composed in Java since it is meant as compatibility layer for the Kotlin inline
 * class.
 */
public class ResultCompatTest {
    @Test
    public void testSuccessfulResult() {
        final var result = ResultCompat.success("Some value");

        assertEquals("ResultCompat(value = Some value)", result.toString());
        assertTrue(result.isSuccess());
        assertFalse(result.isFailure());
        assertNull(result.exceptionOrNull());
        assertEquals("Some value", result.getOrNull());
    }

    @Test
    public void testFailureResult() {
        final var result = ResultCompat.failure(new Exception("Some error"));

        assertEquals("ResultCompat(error = java.lang.Exception: Some error)", result.toString());
        assertFalse(result.isSuccess());
        assertTrue(result.isFailure());
        assertEquals("Some error", Objects.requireNonNull(result.exceptionOrNull()).getMessage());
        assertNull(result.getOrNull());
    }

    @Test
    public void shouldEqualsSuccessCases() {
        final var result1 = ResultCompat.success("Same value");
        final var result2 = ResultCompat.success("Same value");

        assertEquals(result1.hashCode(), result2.hashCode());
        assertEquals(result1, result2);
        //noinspection EqualsWithItself
        assertEquals(result1, result1);
    }

    @Test
    public void shouldNotEqualDifferentSuccessCases() {
        final var result1 = ResultCompat.success("Value 1");
        final var result2 = ResultCompat.success("Value 2");

        assertNotEquals(result1, result2);
        assertNotEquals(result1.hashCode(), result2.hashCode());
        assertNotEquals(result1, new Object());
    }

    @Test
    public void shouldEqualFailureCases() {
        // Exceptions are virtually never equal unless they are exactly the same instance!
        final var exception = new Exception("Same error");
        final var result1 = ResultCompat.failure(exception);
        final var result2 = ResultCompat.failure(exception);

        assertEquals(result1.exceptionOrNull(), result2.exceptionOrNull());
        assertEquals(result1.hashCode(), result2.hashCode());
    }

    @Test
    public void shouldNotEqualDifferentFailureCases() {
        final var result1 = ResultCompat.failure(new Exception("Error 1"));
        final var result2 = ResultCompat.failure(new Exception("Error 2"));

        assertNotEquals(result1, result2);
        assertNotEquals(result1.hashCode(), result2.hashCode());
    }

    @Test
    public void shouldNotEqualSuccessAndFailureCases() {
        final var result1 = ResultCompat.success("Value");
        final var result2 = ResultCompat.failure(new Exception("Error"));

        assertNotEquals(result1, result2);
        assertNotEquals(result1.hashCode(), result2.hashCode());
    }
}
