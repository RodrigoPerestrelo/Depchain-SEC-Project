package depchain.common.crypto;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import threshsig.SigShare;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test: generates all key material in a temporary directory via
 * PKIProvider.generateKeys (ECDSA) and PKIProvider.generateThresholdKeys
 * (threshold), then simulates each node loading its own share + the group
 * key through PKIProvider.
 *
 * No pre-existing key files are required -- every test run is self-contained.
 */
class PKIProviderThreshTest {

    private static final int TOTAL_NODES = 4;

    /** Threshold k – minimum shares needed to produce a valid signature. */
    private static final int K = 3;
    
    /** RSA key size (bits). Kept small here so the test runs quickly. */
    private static final int KEY_BITS = 512;

    /** Temporary directory that holds all generated key files for this test run. */
    private static Path tempKeysDir;

    /** One PKIProvider per simulated node, each loaded from the temp directory. */
    private static PKIProvider[] nodes;

    /** SHA-1 digest of random data – the payload to sign. */
    private static byte[] messageDigest;

    // -------------------------------------------------------------------------
    // Setup – generate keys, then let every peer load them independently
    // -------------------------------------------------------------------------

    @BeforeAll
    static void setUp() throws Exception {
        // Create a temporary directory that will hold all key files.
        tempKeysDir = Files.createTempDirectory("depchain-thresh-test-");
        String keysDir = tempKeysDir.toString();
        System.out.println("[setup] Temporary keys directory: " + keysDir);

        // Generate ECDSA key-pairs (node{i}.pub / node{i}.priv) for all nodes.
        PKIProvider.generateKeys(keysDir, TOTAL_NODES);
        System.out.println("[setup] ECDSA key pairs generated for " + TOTAL_NODES + " nodes");

        // Generate threshold key material (groupkey.properties + node{i}.keyshare).
        // This calls the same logic as GenerateKeys.generateThresholdKeys().
        PKIProvider.generateThresholdKeys(keysDir, K, TOTAL_NODES, KEY_BITS);
        System.out.println("[setup] Threshold keys generated (k=" + K + ", l=" + TOTAL_NODES
                + ", keyBits=" + KEY_BITS + ")");

        // Each peer independently reads its own share + the group key via PKIProvider,
        // just as a real node would at startup.
        nodes = new PKIProvider[TOTAL_NODES];
        for (int i = 0; i < TOTAL_NODES; i++) {
            nodes[i] = new PKIProvider(keysDir, i, TOTAL_NODES);
        }
        System.out.println("[setup] PKIProvider loaded for all " + TOTAL_NODES + " nodes");

        // Build the message digest that will be signed by the tests.
        byte[] data = new byte[1024];
        new Random().nextBytes(data);
        messageDigest = MessageDigest.getInstance("SHA-1").digest(data);

        System.out.println("[setup] GroupKey  k=" + nodes[0].getGroupKey().getK()
                + "  l=" + nodes[0].getGroupKey().getL()
                + "  n=" + nodes[0].getGroupKey().getModulus().bitLength() + " bits");
    }

    @AfterAll
    static void cleanUp() throws IOException {
        // Delete the temporary directory and all its contents.
        if (tempKeysDir != null && Files.exists(tempKeysDir)) {
            Files.walk(tempKeysDir)
                 .sorted(Comparator.reverseOrder())
                 .forEach(p -> {
                     try { Files.delete(p); }
                     catch (IOException ignored) {}
                 });
            System.out.println("[teardown] Temporary keys directory deleted");
        }
    }

    // -------------------------------------------------------------------------
    // Tests – full sign+verify flow
    // -------------------------------------------------------------------------

    // =========================================================================
    // Test 1 – First k nodes sign the digest; the combined shares must verify
    // =========================================================================

    /**
     * The first k nodes sign the digest; the combined shares must verify.
     */
    @Test
    void testThresholdSignAndVerify() throws Exception {
        System.out.println("[test] threshold sign+verify with nodes 0.." + (K - 1) + " ...");

        SigShare[] shares = new SigShare[K];
        for (int i = 0; i < K; i++) {
            shares[i] = nodes[i].threshSign(messageDigest);
            System.out.println("  node " + i + " produced share id=" + shares[i].getId());
        }

        boolean valid = nodes[0].threshVerify(messageDigest, shares);
        System.out.println("[test] verify result: " + valid);
        assertTrue(valid, "k valid SigShares must produce a valid combined signature");
    }

    // =========================================================================
    // Test 2 – A different subset {1,2,3} also produces a valid signature
    // =========================================================================

    /**
     * A different subset {1, 2, 3} of k nodes must also produce a valid signature.
     */
    @Test
    void testDifferentSubset() throws Exception {
        int[] subset = {1, 2, 3};
        System.out.println("[test] threshold sign+verify with subset {1,2,3} ...");

        SigShare[] shares = new SigShare[K];
        for (int i = 0; i < K; i++) {
            shares[i] = nodes[subset[i]].threshSign(messageDigest);
        }

        assertTrue(nodes[1].threshVerify(messageDigest, shares),
                "Subset {1,2,3} of shares must also verify");
    }

    // =========================================================================
    // Test 3 – Verifying shares against a tampered message must fail
    // =========================================================================

    /**
     * Verifying shares against a tampered message must return false.
     */
    @Test
    void testCorruptDataFails() throws Exception {
        System.out.println("[test] corrupted message must not verify ...");

        SigShare[] shares = new SigShare[K];
        for (int i = 0; i < K; i++) {
            shares[i] = nodes[i].threshSign(messageDigest);
        }

        byte[] corrupt = "tampered payload".getBytes();
        boolean valid = nodes[0].threshVerify(corrupt, shares);
        System.out.println("[test] verify corrupted result: " + valid);
        assertFalse(valid, "Shares signed over a different message must not verify");
    }

    // =========================================================================
    // Test 4 – All nodes share identical GroupKey parameters
    // =========================================================================

    /**
     * All PKIProvider instances loaded from the same directory must share
     * identical GroupKey parameters (k, l, modulus, exponent).
     */
    @Test
    void testGroupKeyConsistencyAcrossNodes() {
        System.out.println("[test] GroupKey consistency across all nodes ...");
        var gk0 = nodes[0].getGroupKey();
        for (int i = 1; i < TOTAL_NODES; i++) {
            var gki = nodes[i].getGroupKey();
            assertEquals(gk0.getK(),        gki.getK(),        "k must match for node " + i);
            assertEquals(gk0.getL(),        gki.getL(),        "l must match for node " + i);
            assertEquals(gk0.getModulus(),  gki.getModulus(),  "modulus must match for node " + i);
            assertEquals(gk0.getExponent(), gki.getExponent(), "exponent must match for node " + i);
        }
        System.out.println("[test] All nodes share identical GroupKey parameters");
    }

    // =========================================================================
    // Test 5 – ECDSA sign+verify across all node pairs
    // =========================================================================

    /**
     * Each node must be able to produce a valid ECDSA signature that the other
     * nodes can verify using their copy of the public key.
     */
    @Test
    void testEcdsaSignAndVerify() throws Exception {
        System.out.println("[test] ECDSA sign+verify across nodes ...");
        byte[] payload = "hello depchain".getBytes();

        for (int signer = 0; signer < TOTAL_NODES; signer++) {
            byte[] sig = nodes[signer].sign(payload);
            for (int verifier = 0; verifier < TOTAL_NODES; verifier++) {
                assertTrue(nodes[verifier].verify(payload, sig, signer),
                        "Node " + verifier + " must accept signature from node " + signer);
            }
        }
        System.out.println("[test] ECDSA cross-verification passed for all node pairs");
    }
}
