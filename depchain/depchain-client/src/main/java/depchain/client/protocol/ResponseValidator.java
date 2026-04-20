package depchain.client.protocol;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Validates client responses from blockchain nodes.
 *
 * With the CommitProof-based response model a single valid response is
 * sufficient -- the threshold signature in the CommitProof proves that 2f+1
 * replicas already agreed on the block. The ResponseCollector therefore
 * releases on the first verified response.
 */
public class ResponseValidator {

    public ResponseValidator(int f) {
        // f is retained for API compatibility; no longer controls the threshold.
    }

    /**
     * Collects the response for a single client request.
     *
     * Accepts the first result delivered via complete() -- CommitProof
     * verification is done by the caller before calling complete(), so
     * any result passed here is already proven valid.
     */
    public static class ResponseCollector {
        private final CountDownLatch latch = new CountDownLatch(1);
        private volatile String validatedResult;

        public ResponseCollector() {}

        /**
         * Records a verified result and releases any waiter.
         * Subsequent calls after the first are silently ignored.
         *
         * @param result the result string from the response
         */
        public void complete(String result) {
            if (validatedResult == null) {
                validatedResult = result;
                latch.countDown();
            }
        }

        public String await(long timeout, TimeUnit unit)
                throws InterruptedException, TimeoutException {
            if (!latch.await(timeout, unit)) {
                throw new TimeoutException(
                        "Did not receive a valid CommitProof response in time");
            }
            return validatedResult;
        }
    }
}
