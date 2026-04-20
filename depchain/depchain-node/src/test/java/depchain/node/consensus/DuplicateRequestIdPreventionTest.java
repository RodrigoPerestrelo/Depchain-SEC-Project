package depchain.node.consensus;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.protocol.ClientRequest;
import depchain.common.utils.StaticMembership;
import depchain.node.crypto.ThresholdSignatureService;
import depchain.node.state.ServiceState;
import depchain.node.state.UpcallHandler;
import org.junit.jupiter.api.*;
import threshsig.SigShare;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that verify duplicate PREPARE messages (with same request ID) are rejected.
 *
 * This test simulates the BlockchainMember's protection against duplicate PREPAREs:
 * - BlockchainMember intercepts HOTSTUFF messages before they reach BasicHotStuff
 * - It checks if the request ID has already been executed via UpcallHandler.isRequestAlreadyExecuted()
 * - If yes, the PREPARE is dropped and never reaches consensus
 *
 * Scenarios:
 *   1. Two PREPAREs with same view and same request ID - only first is accepted
 *   2. Two PREPAREs with different views but same request ID - only first is accepted
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DuplicateRequestIdPreventionTest {

    static final int N = 4;
    static final int F = 1;
    static final int K = 2 * F + 1;
    static final int KEY_BITS = 512;
    static final int KEYGEN_MAX_RETRIES = 5;
    static final String DEFAULT_TO = "0x0000000000000000000000000000000000000001";
    static final long DEFAULT_GAS_LIMIT = 30000L;
    static final long DEFAULT_GAS_PRICE = 1L;

    static Path tempKeysDir;
    static PKIProvider[] pkis;

    @BeforeAll
    static void generateKeyMaterial() throws Exception {
        Exception lastError = null;

        for (int attempt = 1; attempt <= KEYGEN_MAX_RETRIES; attempt++) {
            tempKeysDir = Files.createTempDirectory("duplicate-reqid-test-");
            try {
                PKIProvider.generateKeys(tempKeysDir.toString(), N);
                PKIProvider.generateThresholdKeys(tempKeysDir.toString(), K, N, KEY_BITS);
                pkis = new PKIProvider[N];
                for (int i = 0; i < N; i++) {
                    pkis[i] = new PKIProvider(tempKeysDir.toString(), i, N);
                }
                return;
            } catch (Exception e) {
                lastError = e;
                cleanUpKeys();
                if (attempt < KEYGEN_MAX_RETRIES) {
                    System.err.println("[DuplicateRequestIdPreventionTest] key generation failed on attempt "
                            + attempt + ", retrying: " + e.getMessage());
                }
            }
        }

        if (lastError != null) {
            throw lastError;
        }
    }

    @AfterAll
    static void cleanUpKeys() throws IOException {
        if (tempKeysDir != null && Files.exists(tempKeysDir)) {
            Files.walk(tempKeysDir).sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.delete(p);
                        } catch (IOException ignored) {
                        }
                    });
        }
    }

    /**
     * Test: Two PREPAREs with same view and same request ID.
     * Expected: Only the first PREPARE should be accepted and voted on.
     * The second PREPARE should be rejected (no second vote).
     */
    @Test
    @Order(1)
    @Timeout(15)
    void duplicatePrepareInSameViewIsRejected() throws Exception {
        System.out.println("\n══════════  TEST: Duplicate PREPARE in same view  ══════════");

        StaticMembership membership = buildMembership();
        int replicaId = 0;
        int clientId = 1;
        int requestId = 42;

        VoteCapture capture = new VoteCapture();
        UpcallHandler handler = new UpcallHandler(new ServiceState(), null, membership, replicaId, null);
        BasicHotStuff replica = new VoteCapturingHotStuff(
                membership,
                replicaId,
                new CaptureNetwork(capture),
                new ThresholdSignatureService(pkis[replicaId], replicaId),
                handler,
                pkis[replicaId]
        );

        // Create wrapper that simulates BlockchainMember's duplicate prevention
        ProtectedConsensusWrapper protectedReplica = new ProtectedConsensusWrapper(replica, handler, pkis[replicaId]);

        try {
            replica.start();

            // ── Client creates valid request ────────────────────────────────────
            ClientRequest req = buildRequest(clientId, requestId, "test-value");
            byte[] validSig = pkis[clientId % N].sign(req.getSigningData());
            req.setSignature(Base64.getEncoder().encodeToString(validSig));

            System.out.println("  Request: clientId=" + clientId + " requestId=" + requestId);

            // ── Create Block and inject PREPARE #1 ─────────────────────────────
            Block genesis = new Block();
            QuorumCertificate genesisQC = new QuorumCertificate(
                    BasicHotStuff.PREPARE, 0, genesis, new SigShare[0]);
            Block block = new Block(genesis, List.of(req));

            HotStuffMessage prepare1 = new HotStuffMessage(
                    BasicHotStuff.PREPARE,
                    1,
                    block,
                    genesisQC
            );

            protectedReplica.handlePrepare(prepare1);
            Thread.sleep(500);

            // ASSERT: First PREPARE should produce a vote
            int votesAfterFirst = capture.prepareVotes.get();
            assertEquals(1, votesAfterFirst,
                    "First PREPARE should produce exactly one vote");
            System.out.println("  ✓ First PREPARE voted (votes=" + votesAfterFirst + ")");

            // ── Simulate execution: mark request as executed ────────────────────
            // This is done by executing the request in the UpcallHandler
            QuorumCertificate mockCommitQC = new QuorumCertificate(
                    BasicHotStuff.COMMIT, 1, block, new SigShare[0]);
            handler.execute(req, mockCommitQC, true);
            System.out.println("  ✓ Request marked as executed");

            // ── Inject PREPARE #2 (same view, same request ID) ─────────────────
            HotStuffMessage prepare2 = new HotStuffMessage(
                    BasicHotStuff.PREPARE,
                    1,
                    block,
                    genesisQC
            );

            protectedReplica.handlePrepare(prepare2);
            Thread.sleep(500);

            // ASSERT: Second PREPARE should NOT produce another vote
            // (because protectedReplica drops it before it reaches consensus)
            int votesAfterSecond = capture.prepareVotes.get();
            assertEquals(1, votesAfterSecond,
                    "Second PREPARE (same view, same reqId) should NOT produce another vote");
            System.out.println("  ✓ Second PREPARE correctly rejected (votes still=" + votesAfterSecond + ")");

        } finally {
            replica.shutdown();
        }

        System.out.println("  PASS ✓");
    }

    /**
     * Test: Two PREPAREs with different views but same request ID.
     * Expected: Only the first PREPARE should be accepted and voted on.
     * After advancing to view 2, a PREPARE with the same request ID
     * should be rejected (no vote in view 2).
     */
    @Test
    @Order(2)
    @Timeout(15)
    void duplicatePrepareInDifferentViewIsRejected() throws Exception {
        System.out.println("\n══════════  TEST: Duplicate PREPARE in different view  ══════════");

        StaticMembership membership = buildMembership();
        int replicaId = 0;
        int clientId = 1;
        int requestId = 99;

        VoteCapture capture = new VoteCapture();
        UpcallHandler handler = new UpcallHandler(new ServiceState(), null, membership, replicaId, null);
        BasicHotStuff replica = new VoteCapturingHotStuff(
                membership,
                replicaId,
                new CaptureNetwork(capture),
                new ThresholdSignatureService(pkis[replicaId], replicaId),
                handler,
                pkis[replicaId]
        );

        // Create wrapper that simulates BlockchainMember's duplicate prevention
        ProtectedConsensusWrapper protectedReplica = new ProtectedConsensusWrapper(replica, handler, pkis[replicaId]);

        try {
            replica.start();

            // ── Client creates valid request ────────────────────────────────────
            ClientRequest req = buildRequest(clientId, requestId, "view1-value");
            byte[] validSig = pkis[clientId % N].sign(req.getSigningData());
            req.setSignature(Base64.getEncoder().encodeToString(validSig));

            System.out.println("  Request: clientId=" + clientId + " requestId=" + requestId);

            // ── VIEW 1: Inject PREPARE with request ────────────────────────────
            Block genesis = new Block();
            QuorumCertificate genesisQC = new QuorumCertificate(
                    BasicHotStuff.PREPARE, 0, genesis, new SigShare[0]);
            Block blockView1 = new Block(genesis, List.of(req));

            HotStuffMessage prepareView1 = new HotStuffMessage(
                    BasicHotStuff.PREPARE,
                    1,
                    blockView1,
                    genesisQC
            );

            protectedReplica.handlePrepare(prepareView1);
            Thread.sleep(500);

            // ASSERT: View 1 PREPARE should produce a vote
            int votesInView1 = capture.prepareVotes.get();
            assertEquals(1, votesInView1,
                    "PREPARE in view 1 should produce exactly one vote");
            System.out.println("  ✓ View 1: PREPARE voted (votes=" + votesInView1 + ")");

            // ── Simulate full consensus cycle to DECIDE ────────────────────────
            // Complete PREPARE → PRE-COMMIT → COMMIT → DECIDE phases
            SigShare[] emptyShares = new SigShare[0];

            QuorumCertificate prepareQC = new QuorumCertificate(
                    BasicHotStuff.PREPARE, 1, blockView1, emptyShares);
            HotStuffMessage preCommit = new HotStuffMessage(
                    BasicHotStuff.PRE_COMMIT, 1, null, prepareQC);
            replica.addMessageToQueue(preCommit);
            Thread.sleep(300);

            QuorumCertificate preCommitQC = new QuorumCertificate(
                    BasicHotStuff.PRE_COMMIT, 1, blockView1, emptyShares);
            HotStuffMessage commit = new HotStuffMessage(
                    BasicHotStuff.COMMIT, 1, null, preCommitQC);
            replica.addMessageToQueue(commit);
            Thread.sleep(300);

            QuorumCertificate commitQC = new QuorumCertificate(
                    BasicHotStuff.COMMIT, 1, blockView1, emptyShares);
            HotStuffMessage decide = new HotStuffMessage(
                    BasicHotStuff.DECIDE, 1, null, commitQC);
            replica.addMessageToQueue(decide);
            Thread.sleep(500);

            System.out.println("  ✓ View 1: Completed consensus and executed request");

            // ── VIEW 2: Inject PREPARE with same request ID ────────────────────
            // Clear vote counter to start fresh for view 2
            int votesBeforeView2 = capture.prepareVotes.get();

            // Create a new block for view 2 (but with same request)
            Block blockView2 = new Block(genesis, List.of(req));

            HotStuffMessage prepareView2 = new HotStuffMessage(
                    BasicHotStuff.PREPARE,
                    2,
                    blockView2,
                    genesisQC
            );

            protectedReplica.handlePrepare(prepareView2);
            Thread.sleep(500);

            // ASSERT: View 2 PREPARE should NOT produce a vote (request already executed)
            // protectedReplica drops it before it reaches consensus
            int votesAfterView2 = capture.prepareVotes.get();
            assertEquals(votesBeforeView2, votesAfterView2,
                    "PREPARE in view 2 (same reqId) should NOT produce a vote");
            System.out.println("  ✓ View 2: Duplicate PREPARE correctly rejected (votes=" + votesAfterView2 + ")");

        } finally {
            replica.shutdown();
        }

        System.out.println("  PASS ✓");
    }

    /**
     * Test: Two PREPAREs with same view, same request ID but different values.
     * Expected: First PREPARE is accepted. Second PREPARE (even with different value)
     * is rejected because the request ID was already executed.
     */
    @Test
    @Order(3)
    @Timeout(15)
    void duplicatePrepareWithDifferentValueInSameViewIsRejected() throws Exception {
        System.out.println("\n══════════  TEST: Duplicate PREPARE (different value) in same view  ══════════");

        StaticMembership membership = buildMembership();
        int replicaId = 0;
        int clientId = 1;
        int requestId = 123;

        VoteCapture capture = new VoteCapture();
        UpcallHandler handler = new UpcallHandler(new ServiceState(), null, membership, replicaId, null);
        BasicHotStuff replica = new VoteCapturingHotStuff(
                membership,
                replicaId,
                new CaptureNetwork(capture),
                new ThresholdSignatureService(pkis[replicaId], replicaId),
                handler,
                pkis[replicaId]
        );

        // Create wrapper that simulates BlockchainMember's duplicate prevention
        ProtectedConsensusWrapper protectedReplica = new ProtectedConsensusWrapper(replica, handler, pkis[replicaId]);

        try {
            replica.start();

            // ── Client creates first request ────────────────────────────────────
            ClientRequest req1 = buildRequest(clientId, requestId, "value-A");
            byte[] sig1 = pkis[clientId % N].sign(req1.getSigningData());
            req1.setSignature(Base64.getEncoder().encodeToString(sig1));

            System.out.println("  Request 1: clientId=" + clientId + " requestId=" + requestId + " value=value-A");

            // ── Inject PREPARE #1 ───────────────────────────────────────────────
            Block genesis = new Block();
            QuorumCertificate genesisQC = new QuorumCertificate(
                    BasicHotStuff.PREPARE, 0, genesis, new SigShare[0]);
            Block block1 = new Block(genesis, List.of(req1));

            HotStuffMessage prepare1 = new HotStuffMessage(
                    BasicHotStuff.PREPARE,
                    1,
                    block1,
                    genesisQC
            );

            protectedReplica.handlePrepare(prepare1);
            Thread.sleep(500);

            // ASSERT: First PREPARE should produce a vote
            int votesAfterFirst = capture.prepareVotes.get();
            assertEquals(1, votesAfterFirst,
                    "First PREPARE should produce exactly one vote");
            System.out.println("  ✓ First PREPARE voted (votes=" + votesAfterFirst + ")");

            // ── Simulate execution ──────────────────────────────────────────────
            QuorumCertificate mockCommitQC = new QuorumCertificate(
                    BasicHotStuff.COMMIT, 1, block1, new SigShare[0]);
            handler.execute(req1, mockCommitQC, true);
            System.out.println("  ✓ Request 1 marked as executed");

            // ── Create second request (SAME request ID, DIFFERENT value) ───────
            ClientRequest req2 = buildRequest(clientId, requestId, "value-B");
            byte[] sig2 = pkis[clientId % N].sign(req2.getSigningData());
            req2.setSignature(Base64.getEncoder().encodeToString(sig2));

            System.out.println("  Request 2: clientId=" + clientId + " requestId=" + requestId + " value=value-B");

            Block block2 = new Block(genesis, List.of(req2));

            HotStuffMessage prepare2 = new HotStuffMessage(
                    BasicHotStuff.PREPARE,
                    1,
                    block2,
                    genesisQC
            );

            protectedReplica.handlePrepare(prepare2);
            Thread.sleep(500);

            // ASSERT: Second PREPARE should NOT produce another vote
            // protectedReplica drops it before it reaches consensus
            int votesAfterSecond = capture.prepareVotes.get();
            assertEquals(1, votesAfterSecond,
                    "Second PREPARE (same view, same reqId, different value) should NOT produce another vote");
            System.out.println("  ✓ Second PREPARE correctly rejected (votes still=" + votesAfterSecond + ")");

        } finally {
            replica.shutdown();
        }

        System.out.println("  PASS ✓");
    }

    private static StaticMembership buildMembership() {
        List<StaticMembership.NodeInfo> ns = new ArrayList<>();
        ns.add(new StaticMembership.NodeInfo(0, "127.0.0.1", 9000));
        ns.add(new StaticMembership.NodeInfo(1, "127.0.0.1", 9001));
        ns.add(new StaticMembership.NodeInfo(2, "127.0.0.1", 9002));
        ns.add(new StaticMembership.NodeInfo(3, "127.0.0.1", 9003));
        return new StaticMembership(F, ns);
    }

    private static class VoteCapture {
        final AtomicInteger prepareVotes = new AtomicInteger(0);
    }

    /**
     * Network that captures votes sent by replicas.
     */
    private static class CaptureNetwork implements Network {
        private final VoteCapture capture;

        CaptureNetwork(VoteCapture capture) {
            this.capture = capture;
        }

        @Override
        public void send(InetAddress destIp, int destPort, Message msg) {
            // Check if this is a PREPARE vote
            if ("HOTSTUFF".equals(msg.getType())) {
                try {
                    HotStuffMessage hsMsg = HotStuffMessage.fromJson(msg.getContent());
                    if (BasicHotStuff.PREPARE.equals(hsMsg.getType()) && hsMsg.getPartialSig() != null) {
                        capture.prepareVotes.incrementAndGet();
                    }
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static class VoteCapturingHotStuff extends BasicHotStuff {
        VoteCapturingHotStuff(StaticMembership membership,
                              int myId,
                              Network network,
                              ThresholdSignatureService tss,
                              UpcallHandler upcallHandler,
                              PKIProvider pki) {
            super(membership, myId, network, tss, upcallHandler, pki);
        }
    }

    /**
     * Wrapper that simulates BlockchainMember's duplicate PREPARE prevention.
     * Intercepts PREPAREs and checks if the request ID was already executed
     * before forwarding to consensus.
     */
    private static class ProtectedConsensusWrapper {
        private final BasicHotStuff consensus;
        private final UpcallHandler upcallHandler;
        private final PKIProvider pki;

        ProtectedConsensusWrapper(BasicHotStuff consensus, UpcallHandler upcallHandler, PKIProvider pki) {
            this.consensus = consensus;
            this.upcallHandler = upcallHandler;
            this.pki = pki;
        }

        /**
         * Simulates BlockchainMember's message handling for HOTSTUFF PREPAREs.
         * Applies the same duplicate prevention logic as in production code.
         */
        void handlePrepare(HotStuffMessage hotMsg) {
            // Verify client signature in block (as BlockchainMember does)
            Block block = hotMsg.getNode();
            if (block != null && !isValidClientSignatureInBlock(block, pki)) {
                System.err.println("Dropped PREPARE with invalid client signature");
                return;
            }

            // Prevent duplicate PREPAREs for the same clientId+requestId
            ClientRequest clientReq = firstTransaction(block);
            if (clientReq != null) {
                int clientId = clientReq.getClientId();
                int requestId = clientReq.getRequestId();

                // Check if this request has already been executed
                if (upcallHandler.isRequestAlreadyExecuted(clientId, requestId)) {
                    System.err.println(String.format(
                            "Dropped PREPARE for already-executed request: clientId=%d requestId=%d",
                            clientId, requestId));
                    return;
                }
            }

            // Forward to consensus
            consensus.addMessageToQueue(hotMsg);
        }

        private boolean isValidClientSignatureInBlock(Block block, PKIProvider pki) {
            if (pki == null) return true; // No PKI = no verification (test mode)

            ClientRequest req = firstTransaction(block);
            if (req == null) return true; // Internal command (e.g., genesis)

            if (req.getSignature() == null || req.getSignature().isEmpty()) {
                return false;
            }

            try {
                byte[] sig = Base64.getDecoder().decode(req.getSignature());
                return pki.verify(req.getSigningData(), sig, req.getClientId());
            } catch (Exception e) {
                return false;
            }
        }

        private ClientRequest firstTransaction(Block block) {
            if (block == null || block.getTransactions() == null || block.getTransactions().isEmpty()) {
                return null;
            }
            return block.getTransactions().get(0);
        }
    }

    private static ClientRequest buildRequest(int clientId, int requestId, String dataText) {
        return new ClientRequest(
                clientId,
                requestId,
                DEFAULT_TO,
                0L,
                DEFAULT_GAS_LIMIT,
                DEFAULT_GAS_PRICE,
                toHex(dataText),
                System.currentTimeMillis());
    }

    private static String toHex(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder("0x");
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
