package io.csaf.retrieval;

import io.ktor.client.HttpClient;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CsafLoaderJavaTest {

    @Test
    void testDefaultConstructor() {
        // Should not crash, default engine + client inside
        CsafLoader loader = new CsafLoader();
        assertNotNull(loader);
    }

    @Test
    void testConstructorWithEngine() {
        CsafLoader loader = new CsafLoader(TestUtilsKt.mockEngine());
        assertNotNull(loader);
    }

    @Test
    void testConstructorWithClient() {
        HttpClient client = CsafLoaderKt.defaultHttpClient(TestUtilsKt.mockEngine());
        CsafLoader loader = new CsafLoader(null, client);
        assertNotNull(loader);
    }

    @Test
    void testFactoryFromClient() {
        HttpClient client = CsafLoaderKt.defaultHttpClient(TestUtilsKt.mockEngine());
        CsafLoader loader = CsafLoader.fromClient(client);
        assertNotNull(loader);
    }

    @Test
    void testFactoryFromEngine() {
        CsafLoader loader = CsafLoader.fromEngine(TestUtilsKt.mockEngine());
        assertNotNull(loader);
    }

    @Test
    void testFactoryWithSettings() {
        CsafLoader loader = CsafLoader.withSettings();
        assertNotNull(loader);
    }

    @Test
    void testFactoryWithSettingsAllArgs() {
        CsafLoader loader = CsafLoader.withSettings(
                10,   // maxRetries
                3.0,  // retryBase
                500,  // retryBaseDelayMs
                20000, // retryMaxDelayMs
                TestUtilsKt.mockEngine() // engine
        );
        assertNotNull(loader);
    }

    @Test
    void testGetLazyLoader() {
        CsafLoader loader = CsafLoader.getLazyLoader();
        assertNotNull(loader);
    }
}