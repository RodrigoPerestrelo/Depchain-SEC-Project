package depchain.client.protocol;

import org.junit.jupiter.api.*;

import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ResponseValidator.ResponseCollector.
 *
 * With the CommitProof model the collector uses a first-valid-response
 * strategy: the first call to complete() releases the latch. CommitProof
 * verification happens in DepChainClient before complete() is called,
 * so these tests focus on the latch semantics only.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ResponseCollectorTest {

    // =========================================================================
    // Test 1 – No response -> timeout
    // =========================================================================

    /**
     * When no call to complete() is made, await() must throw TimeoutException.
     */
    @Test @Order(1)
    void noResponseCausesTimeout() {
        ResponseValidator.ResponseCollector collector = new ResponseValidator.ResponseCollector();

        assertThrows(TimeoutException.class,
                () -> collector.await(50, TimeUnit.MILLISECONDS),
                "Must time out when no response arrives");
    }

    // =========================================================================
    // Test 2 – First complete() releases the latch
    // =========================================================================

    /**
     * A single call to complete("OK") must release the latch immediately,
     * allowing await() to return the provided value.
     */
    @Test @Order(2)
    void firstCompleteReleasesImmediately() throws Exception {
        ResponseValidator.ResponseCollector collector = new ResponseValidator.ResponseCollector();

        collector.complete("OK");

        String result = collector.await(1, TimeUnit.SECONDS);
        assertEquals("OK", result, "Result must be the value passed to complete()");
    }

    // =========================================================================
    // Test 3 – Second complete() is ignored; original result is preserved
    // =========================================================================

    /**
     * Calling complete() twice must not overwrite the first result.
     * The collector follows a first-valid-response strategy.
     */
    @Test @Order(3)
    void secondCompleteIsIgnored() throws Exception {
        ResponseValidator.ResponseCollector collector = new ResponseValidator.ResponseCollector();

        collector.complete("FIRST");
        collector.complete("SECOND");   // must be silently ignored

        String result = collector.await(1, TimeUnit.SECONDS);
        assertEquals("FIRST", result, "Second complete() must not overwrite the first result");
    }

    // =========================================================================
    // Test 4 – Timeout when complete() is never called
    // =========================================================================

    /**
     * Reinforces test 1: await() must time out when complete() is never
     * invoked, even with a longer deadline.
     */
    @Test @Order(4)
    void timeoutWhenNeverCompleted() {
        ResponseValidator.ResponseCollector collector = new ResponseValidator.ResponseCollector();

        assertThrows(TimeoutException.class,
                () -> collector.await(100, TimeUnit.MILLISECONDS),
                "Should time out when complete() is never called");
    }

    // =========================================================================
    // Test 5 – Concurrent complete() calls are thread-safe; first wins
    // =========================================================================

    /**
     * Four threads race to call complete() concurrently.  Exactly one value
     * must win, and the collector must not throw or return null.
     */
    @Test @Order(5) @Timeout(5)
    void concurrentCompletionsAreSafe() throws Exception {
        ResponseValidator.ResponseCollector collector = new ResponseValidator.ResponseCollector();

        ExecutorService pool = Executors.newFixedThreadPool(4);
        for (int i = 0; i < 4; i++) {
            final String val = "result-" + i;
            pool.submit(() -> collector.complete(val));
        }
        pool.shutdown();

        String result = collector.await(3, TimeUnit.SECONDS);
        assertNotNull(result, "One of the concurrent completions must succeed");
        assertTrue(result.startsWith("result-"), "Result must be one of the submitted values");
    }
}
