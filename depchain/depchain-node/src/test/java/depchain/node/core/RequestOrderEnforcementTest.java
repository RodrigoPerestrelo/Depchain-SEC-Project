package depchain.node.core;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.protocol.ClientRequest;
import depchain.common.utils.StaticMembership;
import depchain.node.consensus.BasicHotStuff;
import depchain.node.crypto.ThresholdSignatureService;
import depchain.node.state.ServiceState;
import depchain.node.state.UpcallHandler;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that verify in-order request delivery enforcement per client
 * in BlockchainMember.
 */
class RequestOrderEnforcementTest {

    private static final int N = 4;
    private static final int F = 1;
    private static final int K = 2 * F + 1;
    private static final int KEY_BITS = 512;
    private static final String DEFAULT_TO = "0x0000000000000000000000000000000000000001";
    private static final long DEFAULT_GAS_LIMIT = 30000L;
    private static final long DEFAULT_GAS_PRICE = 1L;

    private static Path tempKeysDir;

    @AfterAll
    static void cleanUpKeys() throws IOException {
        if (tempKeysDir != null && Files.exists(tempKeysDir)) {
            Files.walk(tempKeysDir)
                    .sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.delete(p);
                        } catch (IOException ignored) {
                        }
                    });
        }
    }

    // =========================================================================
    // Test 1 – Out-of-order request is rejected
    // =========================================================================

    /**
     * A CLIENT_REQUEST with requestId=2 arriving before requestId=1 must be
     * rejected.  Once requestId=1 is delivered, requestId=2 is accepted.
     */
    @Test
    @Timeout(15)
    void outOfOrderRequestIsRejected() throws Exception {
        // Clear any leftover state from previous tests
        BlockchainMember.clearClientState();

        tempKeysDir = Files.createTempDirectory("order-test-");
        PKIProvider.generateKeys(tempKeysDir.toString(), N);
        PKIProvider.generateThresholdKeys(tempKeysDir.toString(), K, N, KEY_BITS);

        int nodeId = 0;
        int clientId = 1;

        PKIProvider verifierPki = new PKIProvider(tempKeysDir.toString(), nodeId, N);
        PKIProvider clientSignerPki = new PKIProvider(tempKeysDir.toString(), clientId, N);

        StaticMembership membership = buildMembership();
        UpcallHandler upcallHandler = new UpcallHandler(new ServiceState());
        RecordingHotStuff consensus = new RecordingHotStuff(
                membership,
                nodeId,
                new NoOpNetwork(),
                new ThresholdSignatureService(verifierPki, nodeId),
                upcallHandler,
                verifierPki
        );

        try {
            Method parse = BlockchainMember.class.getDeclaredMethod(
                    "ParseMessage",
                    Message.class,
                    BasicHotStuff.class,
                    StaticMembership.class,
                    int.class,
                    PKIProvider.class,
                    UpcallHandler.class
            );
            parse.setAccessible(true);

            // Create request with requestId=2 (out of order - should expect requestId=1 first)
            ClientRequest outOfOrderReq = buildRequest(clientId, 2, "value2");
            byte[] sig2 = clientSignerPki.sign(outOfOrderReq.getSigningData());
            outOfOrderReq.setSignature(Base64.getEncoder().encodeToString(sig2));

            Message msg2 = new Message(outOfOrderReq.toJson(), "CLIENT_REQUEST");

            // Try to deliver out-of-order request
            parse.invoke(null, msg2, consensus, membership, nodeId, verifierPki, upcallHandler);

            // ASSERT: out-of-order request must NOT be proposed
            assertEquals(0, consensus.proposeCalls.get(),
                    "Out-of-order request (requestId=2 before requestId=1) must be rejected");

            // Now send requestId=1 (correct order)
            ClientRequest inOrderReq = buildRequest(clientId, 1, "value1");
            byte[] sig1 = clientSignerPki.sign(inOrderReq.getSigningData());
            inOrderReq.setSignature(Base64.getEncoder().encodeToString(sig1));

            Message msg1 = new Message(inOrderReq.toJson(), "CLIENT_REQUEST");
            parse.invoke(null, msg1, consensus, membership, nodeId, verifierPki, upcallHandler);

            // ASSERT: in-order request MUST be accepted
            assertEquals(1, consensus.proposeCalls.get(),
                    "In-order request (requestId=1) must be accepted");

            // Now retry requestId=2 (now it should be accepted as it's next in sequence)
            consensus.proposeCalls.set(0); // reset counter
            parse.invoke(null, msg2, consensus, membership, nodeId, verifierPki, upcallHandler);

            assertEquals(1, consensus.proposeCalls.get(),
                    "Request requestId=2 should now be accepted after requestId=1");

        } finally {
            consensus.shutdown();
        }
    }

    // =========================================================================
    // Test 2 – Multiple clients have independent request ID sequences
    // =========================================================================

    /**
     * Client A and Client B each maintain independent request counters.
     * Both clients sending requestId=1 must succeed, and an out-of-order
     * request from Client A must not affect Client B's sequence.
     */
    @Test
    @Timeout(15)
    void multipleClientsHaveIndependentSequences() throws Exception {
        // Clear any leftover state from previous tests
        BlockchainMember.clearClientState();

        tempKeysDir = Files.createTempDirectory("multiclient-order-test-");
        PKIProvider.generateKeys(tempKeysDir.toString(), N);
        PKIProvider.generateThresholdKeys(tempKeysDir.toString(), K, N, KEY_BITS);

        int nodeId = 0;
        int clientA = 1;
        int clientB = 2;

        PKIProvider verifierPki = new PKIProvider(tempKeysDir.toString(), nodeId, N);
        PKIProvider clientAPki = new PKIProvider(tempKeysDir.toString(), clientA, N);
        PKIProvider clientBPki = new PKIProvider(tempKeysDir.toString(), clientB, N);

        StaticMembership membership = buildMembership();
        UpcallHandler upcallHandler = new UpcallHandler(new ServiceState());
        RecordingHotStuff consensus = new RecordingHotStuff(
                membership,
                nodeId,
                new NoOpNetwork(),
                new ThresholdSignatureService(verifierPki, nodeId),
                upcallHandler,
                verifierPki
        );

        try {
            Method parse = BlockchainMember.class.getDeclaredMethod(
                    "ParseMessage",
                    Message.class,
                    BasicHotStuff.class,
                    StaticMembership.class,
                    int.class,
                    PKIProvider.class,
                    UpcallHandler.class
            );
            parse.setAccessible(true);

            // Client A sends requestId=1
            ClientRequest reqA1 = buildRequest(clientA, 1, "A1");
            byte[] sigA1 = clientAPki.sign(reqA1.getSigningData());
            reqA1.setSignature(Base64.getEncoder().encodeToString(sigA1));
            parse.invoke(null, new Message(reqA1.toJson(), "CLIENT_REQUEST"), consensus, membership, nodeId, verifierPki, upcallHandler);

            // Client B sends requestId=1 (independent sequence from A)
            ClientRequest reqB1 = buildRequest(clientB, 1, "B1");
            byte[] sigB1 = clientBPki.sign(reqB1.getSigningData());
            reqB1.setSignature(Base64.getEncoder().encodeToString(sigB1));
            parse.invoke(null, new Message(reqB1.toJson(), "CLIENT_REQUEST"), consensus, membership, nodeId, verifierPki, upcallHandler);

            // ASSERT: both should be accepted (independent sequences)
            assertEquals(2, consensus.proposeCalls.get(),
                    "Both clients should have independent sequences - both requestId=1 accepted");

            // Client A sends requestId=3 (out of order - expects 2)
            ClientRequest reqA3 = buildRequest(clientA, 3, "A3");
            byte[] sigA3 = clientAPki.sign(reqA3.getSigningData());
            reqA3.setSignature(Base64.getEncoder().encodeToString(sigA3));
            parse.invoke(null, new Message(reqA3.toJson(), "CLIENT_REQUEST"), consensus, membership, nodeId, verifierPki, upcallHandler);

            // ASSERT: Client A's out-of-order request should be rejected
            assertEquals(2, consensus.proposeCalls.get(),
                    "Client A's out-of-order requestId=3 should be rejected");

            // Client B sends requestId=2 (correct order)
            ClientRequest reqB2 = buildRequest(clientB, 2, "B2");
            byte[] sigB2 = clientBPki.sign(reqB2.getSigningData());
            reqB2.setSignature(Base64.getEncoder().encodeToString(sigB2));
            parse.invoke(null, new Message(reqB2.toJson(), "CLIENT_REQUEST"), consensus, membership, nodeId, verifierPki, upcallHandler);

            // ASSERT: Client B's in-order request should be accepted
            assertEquals(3, consensus.proposeCalls.get(),
                    "Client B sequence is independent - requestId=2 should be accepted");

        } finally {
            consensus.shutdown();
        }
    }

    private static StaticMembership buildMembership() {
        List<StaticMembership.NodeInfo> ns = new ArrayList<>();
        ns.add(new StaticMembership.NodeInfo(0, "127.0.0.1", 9000));
        ns.add(new StaticMembership.NodeInfo(1, "127.0.0.1", 9001));
        ns.add(new StaticMembership.NodeInfo(2, "127.0.0.1", 9002));
        ns.add(new StaticMembership.NodeInfo(3, "127.0.0.1", 9003));
        return new StaticMembership(F, ns);
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

    private static final class NoOpNetwork implements Network {
        @Override
        public void send(java.net.InetAddress destIp, int destPort, Message msg) {
            // no-op for this unit test
        }
    }

    private static final class RecordingHotStuff extends BasicHotStuff {
        final AtomicInteger proposeCalls = new AtomicInteger();

        RecordingHotStuff(StaticMembership membership,
                          int myId,
                          Network network,
                          ThresholdSignatureService tss,
                          UpcallHandler upcallHandler,
                          PKIProvider pki) {
            super(membership, myId, network, tss, upcallHandler, pki);
        }

        @Override
        public void proposeCommand(ClientRequest command) {
            proposeCalls.incrementAndGet();
            super.proposeCommand(command);
        }
    }
}
