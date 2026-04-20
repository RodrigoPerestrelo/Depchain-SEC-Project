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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the gas deduction mechanism.
 *
 * Verifies:
 *   - Exact gas fee deduction from sender for native transfers (21000 * gasPrice)
 *   - Exact gas fee credit to the miner (leader)
 *   - Gas deduction for smart contract calls (actual gas used * gasPrice)
 *   - Out-of-gas transactions still charge gasLimit * gasPrice
 *   - The min(gas_price * gas_limit, gas_price * gas_used) formula
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class GasDeductionTest {

    static final int NODE_ID = 0;
    static final int CLIENT_0 = 0;
    static final long INITIAL_BALANCE = 1_000_000L;

    // ISTCoin contract address for SC tests
    static final String ISTCOIN_ADDRESS = "0x8f7a45ebde059392e46a46dcc14ab24681a961ea";
    static final String SEL_BALANCE_OF = "0x70a08231";

    // ── Infrastructure ────────────────────────────────────────────────────────

    static final class CapturingNetwork implements Network {
        final BlockingQueue<Message> sent = new LinkedBlockingQueue<>();
        @Override
        public void send(InetAddress destIp, int destPort, Message msg) { sent.offer(msg); }
        Message awaitNext(long ms) throws InterruptedException { return sent.poll(ms, TimeUnit.MILLISECONDS); }
    }

    private static StaticMembership membership() {
        List<StaticMembership.NodeInfo> nodes =
                List.of(new StaticMembership.NodeInfo(NODE_ID, "127.0.0.1", 9000));
        List<StaticMembership.NodeInfo> clients = List.of(
                new StaticMembership.NodeInfo(CLIENT_0, "127.0.0.1", 11100),
                new StaticMembership.NodeInfo(1, "127.0.0.1", 11101),
                new StaticMembership.NodeInfo(2, "127.0.0.1", 11102));
        return new StaticMembership(1, nodes, clients);
    }

    private static String clientAddr(int id) {
        return String.format("0x00000000000000000000000000000000000000c%x", id);
    }

    private static String minerAddr(int nodeId) {
        return String.format("0x00000000000000000000000000000000000000a%x", nodeId);
    }

    private static void fundAccount(ServiceState state, String hex, long balance) {
        Address addr = Address.fromHexString(hex);
        var updater = state.getWorld().updater();
        var acc = updater.getOrCreate(addr);
        acc.setBalance(Wei.of(balance));
        updater.commit();
    }

    private static long getBalance(ServiceState state, String hex) {
        var acc = state.getWorld().get(Address.fromHexString(hex));
        return acc != null ? acc.getBalance().toLong() : 0L;
    }

    private static ClientResponse exec(UpcallHandler handler, CapturingNetwork net,
                                        ClientRequest req) throws Exception {
        handler.execute(req);
        Message msg = net.awaitNext(2000);
        assertNotNull(msg, "Expected CLIENT_RESPONSE for requestId=" + req.getRequestId());
        return ClientResponse.fromJson(msg.getContent());
    }

    /** Left-pad a hex string to 64 hex chars (32 bytes). */
    private static String padLeft(String hex) {
        if (hex.startsWith("0x")) hex = hex.substring(2);
        return String.format("%64s", hex).replace(' ', '0');
    }

    // =========================================================================
    // Test 1 – Native transfer charges exactly 21000 * gasPrice
    // =========================================================================

    @Test @Order(1)
    void nativeTransferChargesExactGasFee() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasLimit = 30_000L;
        long gasPrice = 2L;
        long transferValue = 500L;
        long expectedGasFee = 21_000L * gasPrice;  // intrinsic gas for simple transfer

        long senderBefore = getBalance(state, clientAddr(CLIENT_0));

        // Simple native DepCoin transfer (empty data, receiver is another address)
        ClientRequest req = new ClientRequest(
                CLIENT_0, 1,
                clientAddr(1),      // send to client 1
                transferValue,
                gasLimit, gasPrice,
                "",                  // empty data = simple transfer
                System.currentTimeMillis());
        ClientResponse resp = exec(handler, net, req);
        assertTrue(resp.isSuccess(), "Native transfer must succeed: " + resp.getResult());

        long senderAfter = getBalance(state, clientAddr(CLIENT_0));
        long expectedSenderBalance = senderBefore - transferValue - expectedGasFee;

        assertEquals(expectedSenderBalance, senderAfter,
                String.format("Sender must lose exactly value(%d) + gasFee(%d) = %d DepCoin",
                        transferValue, expectedGasFee, transferValue + expectedGasFee));
    }

    // =========================================================================
    // Test 2 – Miner receives exact gas fee as reward
    // =========================================================================

    @Test @Order(2)
    void minerReceivesExactGasFeeReward() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasPrice = 3L;
        long expectedGasFee = 21_000L * gasPrice;

        long minerBefore = getBalance(state, minerAddr(NODE_ID));

        ClientRequest req = new ClientRequest(
                CLIENT_0, 1,
                clientAddr(1), 100L,
                30_000L, gasPrice,
                "",
                System.currentTimeMillis());
        assertTrue(exec(handler, net, req).isSuccess());

        long minerAfter = getBalance(state, minerAddr(NODE_ID));
        assertEquals(minerBefore + expectedGasFee, minerAfter,
                "Miner must receive exactly 21000 * gasPrice = " + expectedGasFee + " DepCoin");
    }

    // =========================================================================
    // Test 3 – Out-of-gas charges gasLimit * gasPrice (the max)
    // =========================================================================

    @Test @Order(3)
    void outOfGasChargesGasLimitTimesGasPrice() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Use a gasLimit smaller than 21000 for a native transfer -> out of gas
        long gasLimit = 10_000L;
        long gasPrice = 2L;
        long expectedGasFee = gasLimit * gasPrice;  // OOG charges full gasLimit

        long senderBefore = getBalance(state, clientAddr(CLIENT_0));

        ClientRequest req = new ClientRequest(CLIENT_0, 1,
                clientAddr(1), 0L,
                gasLimit, gasPrice,
                "",
                System.currentTimeMillis());
        ClientResponse resp = exec(handler, net, req);
        assertFalse(resp.isSuccess(), "Transfer with gasLimit < 21000 must fail (out of gas)");
        assertTrue(resp.getResult().contains("OUT_OF_GAS"), "Must report out of gas: " + resp.getResult());

        long senderAfter = getBalance(state, clientAddr(CLIENT_0));
        assertEquals(senderBefore - expectedGasFee, senderAfter,
                "Out-of-gas must charge exactly gasLimit * gasPrice = " + expectedGasFee);
    }

    // =========================================================================
    // Test 4 – Successful SC call charges gas_used * gasPrice (< gasLimit)
    // =========================================================================

    @Test @Order(4)
    void smartContractCallChargesActualGasUsed() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasLimit = 100_000L;
        long gasPrice = 1L;

        long senderBefore = getBalance(state, clientAddr(CLIENT_0));

        // Call balanceOf on ISTCoin — a read-only SC call that uses much less than 100k gas
        String data = SEL_BALANCE_OF + padLeft(clientAddr(CLIENT_0));
        ClientRequest req = new ClientRequest(CLIENT_0, 1,
                ISTCOIN_ADDRESS, 0L,
                gasLimit, gasPrice,
                data,
                System.currentTimeMillis());
        ClientResponse resp = exec(handler, net, req);
        assertTrue(resp.isSuccess(), "SC balanceOf call must succeed: " + resp.getResult());

        long senderAfter = getBalance(state, clientAddr(CLIENT_0));
        long actualGasCharged = senderBefore - senderAfter;

        // gas_used must be > 0 and < gasLimit
        assertTrue(actualGasCharged > 0, "Must charge some gas");
        assertTrue(actualGasCharged < gasLimit * gasPrice,
                String.format("Actual gas charged (%d) must be less than gasLimit*gasPrice (%d) " +
                              "— this proves the min() formula works", actualGasCharged, gasLimit * gasPrice));
    }

    // =========================================================================
    // Test 5 – Reverted SC call charges gasLimit * gasPrice (penalty)
    // =========================================================================

    @Test @Order(5)
    void revertedSmartContractCallChargesFullGasLimit() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasLimit = 50_000L;
        long gasPrice = 2L;
        long expectedGasFee = gasLimit * gasPrice;

        long senderBefore = getBalance(state, clientAddr(CLIENT_0));

        // Force a revert: approve non-zero to non-zero on ISTCoin
        // First approve 100
        String approveData100 = "0x095ea7b3" +
                padLeft(clientAddr(1)) +
                padLeft(java.math.BigInteger.valueOf(100).toString(16));
        ClientRequest approve100 = new ClientRequest(CLIENT_0, 1,
                ISTCOIN_ADDRESS, 0L, gasLimit, gasPrice,
                approveData100, System.currentTimeMillis());
        exec(handler, net, approve100); // succeeds

        long balanceAfterApprove = getBalance(state, clientAddr(CLIENT_0));

        // Now approve 50 directly (non-zero->non-zero -> REVERT)
        String approveData50 = "0x095ea7b3" +
                padLeft(clientAddr(1)) +
                padLeft(java.math.BigInteger.valueOf(50).toString(16));
        ClientRequest approve50 = new ClientRequest(CLIENT_0, 2,
                ISTCOIN_ADDRESS, 0L, gasLimit, gasPrice,
                approveData50, System.currentTimeMillis());
        ClientResponse resp = exec(handler, net, approve50);
        assertFalse(resp.isSuccess(), "Non-zero to non-zero approve must revert");

        long balanceAfterRevert = getBalance(state, clientAddr(CLIENT_0));
        long gasCharged = balanceAfterApprove - balanceAfterRevert;

        assertEquals(expectedGasFee, gasCharged,
                "Reverted SC call must charge exactly gasLimit * gasPrice = " + expectedGasFee +
                " as penalty (got " + gasCharged + ")");
    }

    // =========================================================================
    // Test 6 – Gas bookkeeping is consistent: sender loss = miner gain
    // =========================================================================

    @Test @Order(6)
    void gasFeeConservation_SenderLossEqualsMinerGain() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasPrice = 5L;

        long senderBefore = getBalance(state, clientAddr(CLIENT_0));
        long minerBefore = getBalance(state, minerAddr(NODE_ID));
        long receiverBefore = getBalance(state, clientAddr(1));

        ClientRequest req = new ClientRequest(CLIENT_0, 1,
                clientAddr(1), 200L,
                30_000L, gasPrice, "",
                System.currentTimeMillis());
        assertTrue(exec(handler, net, req).isSuccess());

        long senderAfter = getBalance(state, clientAddr(CLIENT_0));
        long minerAfter = getBalance(state, minerAddr(NODE_ID));
        long receiverAfter = getBalance(state, clientAddr(1));

        long senderLoss = senderBefore - senderAfter;       // value + gasFee
        long minerGain = minerAfter - minerBefore;           // gasFee
        long receiverGain = receiverAfter - receiverBefore;  // value

        assertEquals(200L, receiverGain, "Receiver must gain exactly the transfer value");
        assertEquals(senderLoss, receiverGain + minerGain,
                "Conservation: sender loss must equal receiver gain + miner gain");
        assertEquals(21_000L * gasPrice, minerGain,
                "Miner gain must be exactly the intrinsic gas fee");
    }

    // =========================================================================
    // Test 7 – NATIVE_BALANCE check charges intrinsic gas (21000)
    // =========================================================================

    @Test @Order(7)
    void nativeBalanceCheckChargesIntrinsicGas() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasPrice = 1L;
        long expectedGas = 21_000L;

        long before = getBalance(state, clientAddr(CLIENT_0));

        ClientRequest req = new ClientRequest(CLIENT_0, 1,
                clientAddr(CLIENT_0), 0L,
                30_000L, gasPrice,
                "NATIVE_BALANCE",
                System.currentTimeMillis());
        ClientResponse resp = exec(handler, net, req);
        assertTrue(resp.isSuccess(), "NATIVE_BALANCE check must succeed");
        assertTrue(resp.getResult().contains("Native Balance:"), "Must contain balance data");

        long after = getBalance(state, clientAddr(CLIENT_0));
        assertEquals(before - expectedGas * gasPrice, after,
                "NATIVE_BALANCE check must charge exactly 21000 * gasPrice");
    }
}
