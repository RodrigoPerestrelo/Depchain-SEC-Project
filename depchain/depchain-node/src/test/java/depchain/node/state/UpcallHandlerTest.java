package depchain.node.state;

import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;
import depchain.common.utils.StaticMembership;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.junit.jupiter.api.*;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for UpcallHandler.
 *
 * Tests verify that the handler correctly executes appended values, sends
 * CLIENT_RESPONSE messages to the originating client, deduplicates
 * repeated requests, and handles genesis (non-JSON) commands.
 *
 * No consensus or networking infrastructure is needed: a
 * CapturingNetwork stub captures any outbound messages.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UpcallHandlerTest {

    static final int NODE_ID    = 0;
    static final int CLIENT_ID  = 4;
    static final int CLIENT_PORT = 11100;
    static final String DEFAULT_TO = "0x0000000000000000000000000000000000000001";
    static final long DEFAULT_GAS_LIMIT = 30000L;
    static final long DEFAULT_GAS_PRICE = 1L;

    // =========================================================================
    // Infrastructure – CapturingNetwork
    // =========================================================================

    /** Records every Message sent via Network#send. */
    static final class CapturingNetwork implements Network {
        final BlockingQueue<Message> sent = new LinkedBlockingQueue<>();

        @Override
        public void send(InetAddress destIp, int destPort, Message msg) {
            sent.offer(msg);
        }

        Message awaitNext(long ms) throws InterruptedException {
            return sent.poll(ms, TimeUnit.MILLISECONDS);
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static StaticMembership membership() {
        List<StaticMembership.NodeInfo> nodes =
                List.of(new StaticMembership.NodeInfo(NODE_ID, "127.0.0.1", 9000));
        List<StaticMembership.NodeInfo> clients =
                List.of(new StaticMembership.NodeInfo(CLIENT_ID, "127.0.0.1", CLIENT_PORT));
        return new StaticMembership(1, nodes, clients);
    }

    private static ClientRequest req(int requestId, String dataText) {
        return new ClientRequest(
                CLIENT_ID,
                requestId,
                DEFAULT_TO,
                0L,
                DEFAULT_GAS_LIMIT,
                DEFAULT_GAS_PRICE,
                toHex(dataText),
                System.currentTimeMillis());
    }

    private static ClientRequest reqWithGas(int requestId, long gasLimit, long gasPrice) {
        return new ClientRequest(
                CLIENT_ID,
                requestId,
                DEFAULT_TO,
                0L,
                gasLimit,
                gasPrice,
                "0x",
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

    /** Helper: adds a funded account to ServiceState for test purposes. */
    private static void fundAccount(ServiceState state, String addressHex, long balance) {
        Address addr = Address.fromHexString(addressHex);
        var updater = state.getWorld().updater();
        var account = updater.getOrCreate(addr);
        account.setBalance(Wei.of(balance));
        updater.commit();
    }

    // =========================================================================
    // Test 1 – Successful APPEND sends CLIENT_RESPONSE("OK")
    // =========================================================================

    @Test @Order(1)
    void appendSendsOkResponse() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        fundAccount(state, "0x00000000000000000000000000000000000000c4", 1000000L);
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        handler.execute(req(1, "hello"));

        Message sent = net.awaitNext(500);
        assertNotNull(sent, "A CLIENT_RESPONSE must be sent after APPEND");
        assertEquals("CLIENT_RESPONSE", sent.getType());

        ClientResponse resp = ClientResponse.fromJson(sent.getContent());
        assertEquals(1, resp.getRequestId());
        assertTrue(resp.isSuccess());
        assertTrue(resp.getResult().startsWith("EVM_TX_SUCCESS"),
            "result must indicate successful EVM execution");
        assertEquals(NODE_ID, resp.getNodeId());
    }

    // =========================================================================
    // Test 2 – Duplicate requestId is ignored (idempotency)
    // =========================================================================

    @Test @Order(2)
    void duplicateRequestIdIgnored() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        fundAccount(state, "0x00000000000000000000000000000000000000c4", 1000000L);
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        handler.execute(req(1, "hello"));
        handler.execute(req(1, "hello"));   // same requestId -> must be ignored

        // First execution sends one response
        Message first = net.awaitNext(500);
        assertNotNull(first, "First execution must send a response");

        // Second execution must NOT send another response
        Message second = net.awaitNext(200);
        assertNull(second, "Duplicate requestId must not trigger a second response");
    }

    // =========================================================================
    // Test 3 – Different requestIds are both executed
    // =========================================================================

    @Test @Order(3)
    void distinctRequestIdsEachExecuted() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        fundAccount(state, "0x00000000000000000000000000000000000000c4", 1000000L);
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        handler.execute(req(1, "tx-A"));
        handler.execute(req(2, "tx-B"));

        Message r1 = net.awaitNext(500);
        Message r2 = net.awaitNext(500);
        assertNotNull(r1, "First request must be executed");
        assertNotNull(r2, "Second request must be executed");

        Set<Integer> requestIds = new HashSet<>();
        requestIds.add(ClientResponse.fromJson(r1.getContent()).getRequestId());
        requestIds.add(ClientResponse.fromJson(r2.getContent()).getRequestId());
        assertEquals(Set.of(1, 2), requestIds, "Both request IDs must appear in responses");
    }

    // =========================================================================
    // Test 4 – Invalid gas params return failure response
    // =========================================================================

    @Test @Order(4)
    void invalidGasParamsReturnFailure() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        fundAccount(state, "0x00000000000000000000000000000000000000c4", 1000000L);
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        ClientRequest badGas = reqWithGas(1, 0L, 0L);
        handler.execute(badGas);

        Message sent = net.awaitNext(500);
        assertNotNull(sent, "A CLIENT_RESPONSE must be sent for invalid gas params");
        ClientResponse resp = ClientResponse.fromJson(sent.getContent());
        assertFalse(resp.isSuccess(), "Invalid gas params must fail");
        assertTrue(resp.getResult().contains("Gas limit and gas price"),
                "result must mention invalid gas params");
    }

    // =========================================================================
    // Test 5 – No-network constructor (test mode): no response sent
    // =========================================================================

    @Test @Order(5)
    void testModeConstructorNoResponse() throws Exception {
        // UpcallHandler(serviceState) is the minimalist constructor used in
        // consensus unit tests; it sets network=null and should not crash.
        UpcallHandler handler = new UpcallHandler(new ServiceState());

        // Must not throw even though network is null
        ClientRequest genesisReq = new ClientRequest(
            CLIENT_ID,
            0,
            DEFAULT_TO,
            0L,
            DEFAULT_GAS_LIMIT,
            DEFAULT_GAS_PRICE,
            "0x",
            System.currentTimeMillis());
        assertDoesNotThrow(() -> handler.execute(req(1, "hello")));
        assertDoesNotThrow(() -> handler.execute(genesisReq));
    }

    // =========================================================================
    // Test 6 – Insufficient balance fails
    // =========================================================================

    @Test @Order(6)
    void insufficientBalanceFails() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        fundAccount(state, "0x00000000000000000000000000000000000000c4", 0L);
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        ClientRequest expensive = new ClientRequest(
                CLIENT_ID,
                1,
                DEFAULT_TO,
                0L,
                10_000_000L,
                100_000L,
                "0x",
                System.currentTimeMillis());

        handler.execute(expensive);
        Message sent = net.awaitNext(500);
        assertNotNull(sent, "A CLIENT_RESPONSE must be sent for insufficient balance");
        ClientResponse resp = ClientResponse.fromJson(sent.getContent());
        assertFalse(resp.isSuccess(), "Insufficient balance must fail");
        assertTrue(resp.getResult().contains("Insufficient balance to cover gas limit + value"),
                "result must mention insufficient balance");
    }
}
