package depchain.client.core;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.AuthenticatedPerfectLinks;
import depchain.common.network.Message;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;
import depchain.common.protocol.CommitProof;
import threshsig.SigShare;

import org.junit.jupiter.api.*;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for DepChainClient.
 *
 * Setup: N=4 mock node servers using real AuthenticatedPerfectLinks, bypassing
 * the consensus layer entirely. Each mock node immediately responds to any
 * CLIENT_REQUEST with a CLIENT_RESPONSE carrying a pre-built CommitProof.
 *
 * Scenarios:
 *   1. happyPath                                -- all 4 nodes respond with valid CommitProof
 *   2. noCommitProofCausesTimeout               -- all nodes respond without CommitProof -> timeout
 *   3. singleValidResponseSuffices              -- only 1 node responds with CommitProof -> OK
 *   4. multipleSequentialRequests               -- client submits 3 back-to-back requests
 *   5. byzantineNodeForgedCommitProofIsRejected -- 3 nodes send forged proof; 1 honest -> OK
 *   6. allNodesForgedCommitProofCausesTimeout   -- all nodes send forged proof -> timeout
 *   7. multipleClientsConcurrentRequests         -- 3 clients append concurrently
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DepChainClientTest {

    // ── Cluster constants ──────────────────────────────────────────────────────
    static final int N          = 4;
    static final int F          = 1;
    static final int K          = 2 * F + 1;   // threshold = 3
    static final int CLIENT_ID  = 4;            // default test client id
    static final int[] CLIENT_IDS = { 4, 5, 6 };
    static final int[] CLIENT_PORTS = { 11000, 11001, 11002 };
    static int CLIENT_PORT = CLIENT_PORTS[0];
    static int[] NODE_PORTS = { 9100, 9101, 9102, 9103 };

    // ── Shared state (generated once) ─────────────────────────────────────────
    static Path        tempKeysDir;
    static String      nodesPath;
    static String      clientsPath;
    static CommitProof sharedCommitProof;   // pre-built proof for tests

    // =========================================================================
    // Key and config generation
    // =========================================================================

    @BeforeAll
    static void generateKeyMaterial() throws Exception {
        tempKeysDir = Files.createTempDirectory("client-integration-test-");
        nodesPath   = tempKeysDir.resolve("nodes.json").toString();
        clientsPath = tempKeysDir.resolve("clients.json").toString();

        // Use dynamic free UDP ports to avoid collisions across concurrent test runs.
        NODE_PORTS = allocateFreePorts(N);
        CLIENT_PORTS[0] = allocateFreePort();
        CLIENT_PORTS[1] = allocateFreePort();
        CLIENT_PORTS[2] = allocateFreePort();
        CLIENT_PORT = CLIENT_PORTS[0];

        System.out.printf("%n[setup] Key directory: %s%n", tempKeysDir);
        long t = System.currentTimeMillis();

        // N nodes (0..3) + 3 clients (4..6) = N + CLIENT_IDS.length ECDSA key pairs
        PKIProvider.generateKeys(tempKeysDir.toString(), N + CLIENT_IDS.length);

        // Threshold keys for N nodes (threshold k=3, total l=4)
        PKIProvider.generateThresholdKeys(tempKeysDir.toString(), K, N, 1024);

        // Write nodes.json
        writeConfig(Path.of(nodesPath), Path.of(clientsPath));

        // Pre-build a CommitProof by collecting k threshold shares from nodes 0..k-1.
        // The client verifies this proof with the shared GroupKey.
        sharedCommitProof = buildCommitProof();

        System.out.printf("[setup] Keys + config ready in %d ms%n",
                System.currentTimeMillis() - t);
    }

    @AfterAll
    static void cleanUpKeys() throws IOException {
        if (tempKeysDir != null && Files.exists(tempKeysDir))
            Files.walk(tempKeysDir).sorted(Comparator.reverseOrder())
                 .forEach(p -> { try { Files.delete(p); } catch (IOException ignored) {} });
    }

    /**
     * Builds a valid CommitProof for a synthetic block.
     * Uses the first K nodes' threshold key shares to sign the proof data.
     */
    private static CommitProof buildCommitProof() throws Exception {
        String blockHash  = "0000000000000000000000000000000000000000";
        int    viewNumber = 1;
        String type       = "COMMIT";

        // Replicates ThresholdSignatureService.tsign message format
        String msgStr = type + "|" + viewNumber + "|" + blockHash;
        byte[] data   = MessageDigest.getInstance("SHA-1")
                                     .digest(msgStr.getBytes(StandardCharsets.UTF_8));

        // Collect K sig shares from nodes 0..K-1
        SigShare[] sigs = new SigShare[K];
        for (int i = 0; i < K; i++) {
            PKIProvider nodePki = new PKIProvider(tempKeysDir.toString(), i, N + CLIENT_IDS.length, true);
            sigs[i] = nodePki.threshSign(data);
        }
        return new CommitProof(type, viewNumber, blockHash, sigs);
    }

    // =========================================================================
    // Test 1 – Happy path: all nodes respond with valid CommitProof -> client OK
    // =========================================================================

    @Test @Order(1) @Timeout(30)
    void happyPath() throws Exception {
        System.out.println("\n══  CLIENT TEST 1: happyPath  ══");

        List<MockNode> nodes = startMockNodes(N, sharedCommitProof);
        DepChainClient client = new DepChainClient(CLIENT_ID, nodesPath, clientsPath, tempKeysDir.toString());
        try {
            long t = System.currentTimeMillis();
            String result = client.sendTransaction("0x01", 1L, 21000L, 1L, "hello-blockchain");
            System.out.printf("  append returned '%s' in %d ms%n",
                    result, System.currentTimeMillis() - t);
            assertEquals("OK", result);
        } finally {
            client.close();
            shutdown(nodes);
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 2 – Nodes respond WITHOUT CommitProof -> client rejects all -> timeout
    // =========================================================================

    @Test @Order(2) @Timeout(20)
    void noCommitProofCausesTimeout() throws Exception {
        System.out.println("\n══  CLIENT TEST 2: noCommitProofCausesTimeout  ══");

        // Mock nodes send responses with commitProof=null -> client drops them
        List<MockNode> nodes = startMockNodes(N, null);
        DepChainClient client = new DepChainClient(CLIENT_ID, nodesPath, clientsPath, tempKeysDir.toString());
        try {
            Exception ex = assertThrows(Exception.class,
                () -> client.sendTransaction("0x01", 1L, 21000L, 1L,
                    "will-timeout", 5, TimeUnit.SECONDS));
            System.out.println("  Got expected exception: " + ex.getClass().getSimpleName());
        } finally {
            client.close();
            shutdown(nodes);
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 3 – Only a single node responds with a valid CommitProof -> still OK
    //           (CommitProof proves quorum; 1 verified response is sufficient)
    // =========================================================================

    @Test @Order(3) @Timeout(30)
    void singleValidResponseSuffices() throws Exception {
        System.out.println("\n══  CLIENT TEST 3: singleValidResponseSuffices  ══");

        // Node 0: valid CommitProof.  Nodes 1-3: no CommitProof (client drops).
        // The client should succeed as soon as node 0's response arrives.
        List<MockNode> nodes = new ArrayList<>();
        nodes.addAll(startMockNodes(1, sharedCommitProof));   // node 0
        nodes.addAll(startMockNodes(1, 1, N - 1, null));      // nodes 1-3

        DepChainClient client = new DepChainClient(CLIENT_ID, nodesPath, clientsPath, tempKeysDir.toString());
        try {
            long t = System.currentTimeMillis();
            String result = client.sendTransaction("0x01", 1L, 21000L, 1L, "single-proof-test");
            System.out.printf("  append returned '%s' in %d ms%n",
                    result, System.currentTimeMillis() - t);
            assertEquals("OK", result);
        } finally {
            client.close();
            shutdown(nodes);
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 4 – Multiple sequential requests share the same client instance
    // =========================================================================

    @Test @Order(4) @Timeout(60)
    void multipleSequentialRequests() throws Exception {
        System.out.println("\n══  CLIENT TEST 4: multipleSequentialRequests  ══");

        List<MockNode> nodes = startMockNodes(N, sharedCommitProof);
        DepChainClient client = new DepChainClient(CLIENT_ID, nodesPath, clientsPath, tempKeysDir.toString());
        try {
            for (String value : List.of("tx-1", "tx-2", "tx-3")) {
                long t = System.currentTimeMillis();
            String result = client.sendTransaction("0x01", 1L, 21000L, 1L, value);
                System.out.printf("  append('%s') -> '%s' in %d ms%n",
                        value, result, System.currentTimeMillis() - t);
                assertEquals("OK", result);
            }
        } finally {
            client.close();
            shutdown(nodes);
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 5 – Byzantine nodes send a FORGED CommitProof (garbage SigShare bytes)
    //           One honest node still sends a valid proof -> client succeeds
    // =========================================================================

    /**
     * Nodes 0, 1, 2 behave as Byzantine replicas: they respond with a
     * CommitProof whose SigShare bytes are random garbage and will fail
     * threshold verification.
     *
     * Node 3 is honest and sends the pre-built, cryptographically valid proof.
     * The client must discard the three forged proofs and accept the single
     * valid one.
     */
    @Test @Order(5) @Timeout(30)
    void byzantineNodeForgedCommitProofIsRejected() throws Exception {
        System.out.println("\n══  CLIENT TEST 5: byzantineNodeForgedCommitProofIsRejected  ══");

        CommitProof forged = buildForgedCommitProof();
        List<MockNode> nodes = new ArrayList<>();
        nodes.addAll(startMockNodes(3, 0, N, forged));             // nodes 0,1,2 -> forged
        nodes.addAll(startMockNodes(1, 3, N, sharedCommitProof));  // node 3      -> valid

        DepChainClient client = new DepChainClient(CLIENT_ID, nodesPath, clientsPath, tempKeysDir.toString());
        try {
            long t = System.currentTimeMillis();
            String result = client.sendTransaction("0x01", 1L, 21000L, 1L, "forged-proof-test");
            System.out.printf("  append returned '%s' in %d ms%n",
                    result, System.currentTimeMillis() - t);
            assertEquals("OK", result,
                    "Client must accept the one valid CommitProof from the honest node");
        } finally {
            client.close();
            shutdown(nodes);
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 6 – ALL nodes send a forged CommitProof -> client rejects all -> timeout
    // =========================================================================

    /**
     * Every mock node (0-3) responds with a CommitProof whose SigShare bytes
     * are garbage and cannot pass threshold verification.
     * Expected: the client drops every response and append() times out.
     */
    @Test @Order(6) @Timeout(20)
    void allNodesForgedCommitProofCausesTimeout() throws Exception {
        System.out.println("\n══  CLIENT TEST 6: allNodesForgedCommitProofCausesTimeout  ══");

        CommitProof forged = buildForgedCommitProof();
        List<MockNode> nodes = startMockNodes(N, forged);

        DepChainClient client = new DepChainClient(CLIENT_ID, nodesPath, clientsPath, tempKeysDir.toString());
        try {
            Exception ex = assertThrows(Exception.class,
                () -> client.sendTransaction("0x01", 1L, 21000L, 1L,
                    "all-forged", 5, TimeUnit.SECONDS));
            System.out.println("  Got expected exception: " + ex.getClass().getSimpleName());
        } finally {
            client.close();
            shutdown(nodes);
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 7 – Multiple clients append concurrently
    // =========================================================================

    /**
     * Three independent clients (IDs 4, 5, 6) submit transactions concurrently
     * to the same mock-node cluster.  All three must complete successfully,
     * verifying that the protocol supports concurrent multi-client access.
     */
    @Test @Order(7) @Timeout(40)
    void multipleClientsConcurrentRequests() throws Exception {
        System.out.println("\n══  CLIENT TEST 7: multipleClientsConcurrentRequests  ══");

        List<MockNode> nodes = startMockNodes(N, sharedCommitProof);
        List<DepChainClient> clients = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(CLIENT_IDS.length);

        try {
            for (int clientId : CLIENT_IDS) {
                clients.add(new DepChainClient(clientId, nodesPath, clientsPath, tempKeysDir.toString()));
            }

            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < clients.size(); i++) {
                final int idx = i;
                futures.add(pool.submit(() -> clients.get(idx).sendTransaction(
                    "0x01", 1L, 21000L, 1L, "multi-client-tx-" + CLIENT_IDS[idx])));
            }

            for (int i = 0; i < futures.size(); i++) {
                String result = futures.get(i).get(15, TimeUnit.SECONDS);
                assertEquals("OK", result, "client " + CLIENT_IDS[i] + " should complete successfully");
                System.out.printf("  client %d append returned '%s'%n", CLIENT_IDS[i], result);
            }
        } finally {
            pool.shutdownNow();
            for (DepChainClient c : clients) c.close();
            shutdown(nodes);
        }

        System.out.println("  PASS ✓");
    }

    /**
     * Builds a CommitProof containing K garbage SigShares.
     * The share bytes are deterministically random — this proof will always fail
     * threshold verification and simulates a Byzantine node's forged proof.
     */
    private static CommitProof buildForgedCommitProof() {
        byte[] garbage = new byte[128];
        new Random(0xDEADBEEFL).nextBytes(garbage);
        SigShare[] forgeSigs = new SigShare[K];
        for (int i = 0; i < K; i++) {
            forgeSigs[i] = new SigShare(i + 1, garbage.clone());
        }
        return new CommitProof("COMMIT", 1,
                "0000000000000000000000000000000000000000", forgeSigs);
    }

    // =========================================================================
    // Infrastructure – MockNode
    // =========================================================================

    /**
     * Simulates a blockchain node for client protocol testing.
     * Listens on a UDP port and responds immediately to every
     * CLIENT_REQUEST with a CLIENT_RESPONSE carrying
     * the provided commitProof (may be null to simulate
     * a missing proof — the client will reject the response).
     */
    static final class MockNode {
        final int    nodeId;
        final AuthenticatedPerfectLinks apl;
        final PKIProvider pki;
        final CommitProof commitProof;  // null to simulate absent proof
        final Thread listener;
        volatile boolean running = true;

        MockNode(int nodeId, AuthenticatedPerfectLinks apl, PKIProvider pki, CommitProof commitProof) {
            this.nodeId      = nodeId;
            this.apl         = apl;
            this.pki         = pki;
            this.commitProof = commitProof;
            this.listener    = new Thread(() -> {
                while (running) {
                    try {
                        Message msg = apl.deliver();
                        if (!"CLIENT_REQUEST".equals(msg.getType())) continue;

                        ClientRequest req = ClientRequest.fromJson(msg.getContent());

                        // Verify the client's ECDSA signature before responding
                        if (req.getSignature() == null) continue;
                        byte[] reqSig = Base64.getDecoder().decode(req.getSignature());
                        if (!pki.verify(req.getSigningData(), reqSig, req.getClientId())) {
                            System.err.println("[MockNode " + nodeId + "] invalid request signature — dropping");
                            continue;
                        }

                        ClientResponse resp = new ClientResponse(
                                req.getRequestId(), true, "OK", nodeId);

                        // Attach CommitProof (may be null for negative tests)
                        if (commitProof != null) {
                            resp.setCommitProof(commitProof);
                        }

                        InetSocketAddress clientAddr = new InetSocketAddress(
                                "127.0.0.1", clientPortForId(req.getClientId()));
                        Message reply = new Message(resp.toJson(), "CLIENT_RESPONSE");
                        apl.send(clientAddr.getAddress(), clientAddr.getPort(), reply);

                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    } catch (Exception e) {
                        if (running) {
                            System.err.println("[MockNode " + nodeId + "] error: " + e.getMessage());
                        }
                    }
                }
            }, "mock-node-" + nodeId);
            this.listener.setDaemon(true);
        }

        void start() { listener.start(); }

        void shutdown() {
            running = false;
            listener.interrupt();
            apl.close();
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Start count mock nodes starting at node id 0, each with the given proof.
     */
    private List<MockNode> startMockNodes(int count, CommitProof proof) throws Exception {
        return startMockNodes(count, 0, count, proof);
    }

    /**
     * Start count mock nodes starting at id startId.
     */
    private List<MockNode> startMockNodes(int count, int startId, int totalCount,
                                          CommitProof proof) throws Exception {
        List<MockNode> result = new ArrayList<>();
        for (int i = startId; i < startId + count; i++) {
            Map<InetSocketAddress, Integer> peerIds = buildNodePeerIds();
            // Load with threshold keys so ECDSA request-verification works;
            // threshold key material also available (needed for N KEy pairs).
                PKIProvider pki = new PKIProvider(tempKeysDir.toString(), i, N + CLIENT_IDS.length, true);
            AuthenticatedPerfectLinks apl =
                    new AuthenticatedPerfectLinks(NODE_PORTS[i], i, pki, peerIds);
            MockNode node = new MockNode(i, apl, pki, proof);
            node.start();
            result.add(node);
        }
        return result;
    }

    /**
     * Builds the peerIds map for a mock node:
     * maps every other node address + the client address -> their IDs.
     */
    private static Map<InetSocketAddress, Integer> buildNodePeerIds() {
        Map<InetSocketAddress, Integer> peerIds = new HashMap<>();
        for (int j = 0; j < N; j++) {
            peerIds.put(new InetSocketAddress("127.0.0.1", NODE_PORTS[j]), j);
        }
        // Must include all clients so the APL accepts HANDSHAKE/DATA from each one.
        for (int i = 0; i < CLIENT_IDS.length; i++) {
            peerIds.put(new InetSocketAddress("127.0.0.1", CLIENT_PORTS[i]), CLIENT_IDS[i]);
        }
        return peerIds;
    }

    private static int clientPortForId(int clientId) {
        for (int i = 0; i < CLIENT_IDS.length; i++) {
            if (CLIENT_IDS[i] == clientId) return CLIENT_PORTS[i];
        }
        throw new IllegalArgumentException("Unknown client id: " + clientId);
    }

    private static int[] allocateFreePorts(int count) throws IOException {
        int[] ports = new int[count];
        for (int i = 0; i < count; i++) {
            ports[i] = allocateFreePort();
        }
        return ports;
    }

    private static int allocateFreePort() throws IOException {
        try (DatagramSocket s = new DatagramSocket(0)) {
            return s.getLocalPort();
        }
    }

    private static void shutdown(List<MockNode> nodes) {
        for (MockNode n : nodes) n.shutdown();
    }

    /** Writes minimal nodes.json and clients.json for the test cluster. */
    private static void writeConfig(Path nodesPath, Path clientsPath) throws IOException {
        StringBuilder nodesJson = new StringBuilder();
        nodesJson.append("{\n  \"f\": ").append(F).append(",\n  \"nodes\": [\n");
        for (int i = 0; i < N; i++) {
            nodesJson.append("    {\"id\": ").append(i)
              .append(", \"host\": \"127.0.0.1\", \"port\": ").append(NODE_PORTS[i]).append("}");
            if (i < N - 1) nodesJson.append(",");
            nodesJson.append("\n");
        }
        nodesJson.append("  ]\n}");

        StringBuilder clientsJson = new StringBuilder();
        clientsJson.append("{\n  \"clients\": [\n");
        for (int i = 0; i < CLIENT_IDS.length; i++) {
            clientsJson.append("    {\"id\": ").append(CLIENT_IDS[i])
                .append(", \"host\": \"127.0.0.1\", \"port\": ").append(CLIENT_PORTS[i]).append("}");
            if (i < CLIENT_IDS.length - 1) clientsJson.append(",");
            clientsJson.append("\n");
        }
        clientsJson.append("  ]\n}");

        Files.writeString(nodesPath, nodesJson.toString());
        Files.writeString(clientsPath, clientsJson.toString());
    }
}
