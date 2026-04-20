package depchain.node.core;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.protocol.ClientRequest;
import depchain.common.utils.StaticMembership;
import depchain.node.consensus.BasicHotStuff;
import depchain.node.consensus.Block;
import depchain.node.consensus.HotStuffMessage;
import depchain.node.consensus.QuorumCertificate;
import depchain.node.crypto.ThresholdSignatureService;
import depchain.node.state.ServiceState;
import depchain.node.state.UpcallHandler;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import threshsig.SigShare;

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

import static org.junit.jupiter.api.Assertions.assertEquals;

class BlockchainMemberTest {

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
    // Test 1 – Duplicate CLIENT_REQUEST is proposed only once
    // =========================================================================

    /**
     * A duplicate CLIENT_REQUEST delivered to ParseMessage must be proposed
     * only once.  The second delivery is detected as a duplicate and silently
     * dropped (gateway-level deduplication).
     */
    @Test
    @Timeout(15)
    void duplicateClientRequestIsProposedOnlyOnceInParseMessageFlow() throws Exception {
        BlockchainMember.clearClientState();
        tempKeysDir = Files.createTempDirectory("blockchain-member-test-");
        PKIProvider.generateKeys(tempKeysDir.toString(), N);
        PKIProvider.generateThresholdKeys(tempKeysDir.toString(), K, N, KEY_BITS);

        int nodeId = 0;
        int clientId = 1; // reuse an existing key id as the logical client signer

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
            int reqId = 1;
            ClientRequest req = buildRequest(clientId, reqId, "value");
            byte[] sig = clientSignerPki.sign(req.getSigningData());
            req.setSignature(Base64.getEncoder().encodeToString(sig));
            String reqJson = req.toJson();

            Message msg = new Message(reqJson, "CLIENT_REQUEST");

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

            // First delivery: must be accepted and proposed
            parse.invoke(null, msg, consensus, membership, nodeId, verifierPki, upcallHandler);
            // Replay of the same valid request: must be dropped as duplicate
            parse.invoke(null, msg, consensus, membership, nodeId, verifierPki, upcallHandler);

            assertEquals(1, consensus.proposeCalls.get(), "duplicate CLIENT_REQUEST must not be proposed twice");
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
        final AtomicInteger hotStuffEnqueueCalls = new AtomicInteger();

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

        @Override
        public void addMessageToQueue(HotStuffMessage msg) {
            hotStuffEnqueueCalls.incrementAndGet();
            super.addMessageToQueue(msg);
        }
    }
}
