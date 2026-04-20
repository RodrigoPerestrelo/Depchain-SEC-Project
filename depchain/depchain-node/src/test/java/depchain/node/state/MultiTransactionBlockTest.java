package depchain.node.state;

import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;
import depchain.common.utils.StaticMembership;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for multi-transaction block execution.
 *
 * The enunciado requires:
 *   "a proposed block should consist of multiple transactions"
 *   "Transactions should be grouped into blocks and each block should point
 *    to its previous block and represent the world state after executing the
 *    transactions included within the block"
 *
 * These tests simulate the exact flow that BasicHotStuff.executeChain() performs
 * in production (lines 921-942): iterate block.getTransactions() and call
 * upcallHandler.execute() for each transaction sequentially, then verify the
 * cumulative world state after the full block.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MultiTransactionBlockTest {

    static final int NODE_ID = 0;
    static final int CLIENT_0 = 0;
    static final int CLIENT_1 = 1;
    static final int CLIENT_2 = 2;

    static final String ISTCOIN_ADDRESS = "0x8f7a45ebde059392e46a46dcc14ab24681a961ea";
    static final String SEL_TRANSFER   = "0xa9059cbb";
    static final String SEL_BALANCE_OF = "0x70a08231";
    static final String SEL_APPROVE    = "0x095ea7b3";

    static final long GENESIS_NATIVE_BALANCE = 1_000_000L;

    // ── Infrastructure ────────────────────────────────────────────────────────

    static final class CapturingNetwork implements Network {
        final BlockingQueue<Message> sent = new LinkedBlockingQueue<>();
        @Override
        public void send(InetAddress destIp, int destPort, Message msg) { sent.offer(msg); }
        Message awaitNext(long ms) throws InterruptedException { return sent.poll(ms, TimeUnit.MILLISECONDS); }
        void drain() { sent.clear(); }
    }

    private static StaticMembership membership() {
        List<StaticMembership.NodeInfo> nodes =
                List.of(new StaticMembership.NodeInfo(NODE_ID, "127.0.0.1", 9000));
        List<StaticMembership.NodeInfo> clients = List.of(
                new StaticMembership.NodeInfo(CLIENT_0, "127.0.0.1", 11100),
                new StaticMembership.NodeInfo(CLIENT_1, "127.0.0.1", 11101),
                new StaticMembership.NodeInfo(CLIENT_2, "127.0.0.1", 11102));
        return new StaticMembership(1, nodes, clients);
    }

    private static String clientAddr(int id) {
        return String.format("0x00000000000000000000000000000000000000c%x", id);
    }

    private static String minerAddr(int nodeId) {
        return String.format("0x00000000000000000000000000000000000000a%x", nodeId);
    }

    private static long getBalance(ServiceState state, String hex) {
        var acc = state.getWorld().get(Address.fromHexString(hex));
        return acc != null ? acc.getBalance().toLong() : 0L;
    }

    private static String padLeft(String hex) {
        if (hex.startsWith("0x")) hex = hex.substring(2);
        return String.format("%64s", hex).replace(' ', '0');
    }

    private static String encodeAddress(String address) { return padLeft(address); }

    private static String encodeUint256(long value) {
        return padLeft(BigInteger.valueOf(value).toString(16));
    }

    /**
     * Simulates BasicHotStuff.executeChain(): iterate block transactions
     * and call handler.execute() sequentially, collecting responses.
     */
    private static List<ClientResponse> executeBlock(UpcallHandler handler,
                                                      CapturingNetwork net,
                                                      List<ClientRequest> blockTxs) throws Exception {
        List<ClientResponse> responses = new ArrayList<>();
        for (ClientRequest tx : blockTxs) {
            handler.execute(tx);
            Message msg = net.awaitNext(2000);
            assertNotNull(msg, "Expected response for requestId=" + tx.getRequestId() +
                    " clientId=" + tx.getClientId());
            responses.add(ClientResponse.fromJson(msg.getContent()));
        }
        return responses;
    }

    private static long decodeUint256(String hexReturnData) {
        if (hexReturnData.length() >= 64) hexReturnData = hexReturnData.substring(0, 64);
        return new BigInteger(hexReturnData, 16).longValue();
    }

    private static String extractReturnData(String result) {
        if (!result.contains("ReturnData: 0x")) return null;
        return result.substring(result.indexOf("ReturnData: 0x") + 14).trim();
    }

    // =========================================================================
    // Test 1 – Block with 3 native DepCoin transfers, cumulative state is correct
    // =========================================================================

    @Test @Order(1)
    void threeNativeTransfersInOneBlockCumulativeState() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasPrice = 1L;
        long gasLimit = 30_000L;
        long intrinsicGas = 21_000L;

        // Block transactions: ordered by fee (all same fee here, so any order is valid)
        // Tx1: Client 0 sends 100 DepCoin to Client 1
        // Tx2: Client 1 sends 50 DepCoin to Client 2
        // Tx3: Client 2 sends 25 DepCoin to Client 0
        List<ClientRequest> blockTxs = List.of(
                new ClientRequest(CLIENT_0, 1, clientAddr(CLIENT_1), 100L,
                        gasLimit, gasPrice, "", System.currentTimeMillis()),
                new ClientRequest(CLIENT_1, 1, clientAddr(CLIENT_2), 50L,
                        gasLimit, gasPrice, "", System.currentTimeMillis()),
                new ClientRequest(CLIENT_2, 1, clientAddr(CLIENT_0), 25L,
                        gasLimit, gasPrice, "", System.currentTimeMillis())
        );

        List<ClientResponse> responses = executeBlock(handler, net, blockTxs);

        // All 3 must succeed
        for (int i = 0; i < 3; i++) {
            assertTrue(responses.get(i).isSuccess(),
                    "Tx " + i + " must succeed: " + responses.get(i).getResult());
        }

        long gasFee = intrinsicGas * gasPrice;

        // Cumulative state:
        // C0: 1M - 100(sent) + 25(received) - gasFee = 1M - 75 - gasFee
        // C1: 1M + 100(received) - 50(sent) - gasFee = 1M + 50 - gasFee
        // C2: 1M + 50(received) - 25(sent) - gasFee = 1M + 25 - gasFee
        long c0 = getBalance(state, clientAddr(CLIENT_0));
        long c1 = getBalance(state, clientAddr(CLIENT_1));
        long c2 = getBalance(state, clientAddr(CLIENT_2));

        assertEquals(GENESIS_NATIVE_BALANCE - 100 + 25 - gasFee, c0,
                "Client 0 cumulative balance after block");
        assertEquals(GENESIS_NATIVE_BALANCE + 100 - 50 - gasFee, c1,
                "Client 1 cumulative balance after block");
        assertEquals(GENESIS_NATIVE_BALANCE + 50 - 25 - gasFee, c2,
                "Client 2 cumulative balance after block");

        // Miner collects ALL 3 gas fees
        long minerBal = getBalance(state, minerAddr(NODE_ID));
        assertEquals(GENESIS_NATIVE_BALANCE + 3 * gasFee, minerBal,
                "Miner must collect gas fees from all 3 transactions in the block");
    }

    // =========================================================================
    // Test 2 – Block with mixed native + ERC-20 transactions
    // =========================================================================

    @Test @Order(2)
    void mixedNativeAndERC20TransactionsInOneBlock() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long gasPrice = 1L;

        // Tx1: Client 0 native DepCoin transfer of 200 to Client 1
        ClientRequest nativeTransfer = new ClientRequest(CLIENT_0, 1,
                clientAddr(CLIENT_1), 200L,
                30_000L, gasPrice, "", System.currentTimeMillis());

        // Tx2: Client 1 IST Coin ERC-20 transfer of 5000 to Client 2
        String erc20Data = SEL_TRANSFER + encodeAddress(clientAddr(CLIENT_2)) + encodeUint256(5000L);
        ClientRequest erc20Transfer = new ClientRequest(CLIENT_1, 1,
                ISTCOIN_ADDRESS, 0L,
                100_000L, gasPrice, erc20Data, System.currentTimeMillis());

        List<ClientRequest> blockTxs = List.of(nativeTransfer, erc20Transfer);
        List<ClientResponse> responses = executeBlock(handler, net, blockTxs);

        assertTrue(responses.get(0).isSuccess(), "Native transfer must succeed: " + responses.get(0).getResult());
        assertTrue(responses.get(1).isSuccess(), "ERC-20 transfer must succeed: " + responses.get(1).getResult());

        // Verify native balances
        long c0Native = getBalance(state, clientAddr(CLIENT_0));
        long c1Native = getBalance(state, clientAddr(CLIENT_1));
        long intrinsicGas = 21_000L;
        assertEquals(GENESIS_NATIVE_BALANCE - 200 - intrinsicGas * gasPrice, c0Native,
                "C0 native: sent 200 + gas for simple transfer");
        // C1: received 200 DepCoin from C0, paid gas for ERC-20 SC call.
        // ERC-20 transfer gas is typically > 21000 but < 100_000 (our gasLimit).
        // The net effect depends on actual gas used by the EVM.
        long c1GasPaid = GENESIS_NATIVE_BALANCE + 200 - c1Native;
        assertTrue(c1GasPaid > 0, "C1 must have paid some gas");
        assertTrue(c1GasPaid < 100_000L * gasPrice,
                "C1 gas must be less than gasLimit*gasPrice: " + c1GasPaid);

        // Verify IST token balances changed
        // Query IST balance of Client 2 (should have genesis + 5000)
        String balOfData = SEL_BALANCE_OF + encodeAddress(clientAddr(CLIENT_2));
        ClientRequest queryBal = new ClientRequest(CLIENT_0, 2, ISTCOIN_ADDRESS, 0L,
                100_000L, gasPrice, balOfData, System.currentTimeMillis());
        handler.execute(queryBal);
        Message msg = net.awaitNext(2000);
        ClientResponse balResp = ClientResponse.fromJson(msg.getContent());
        assertTrue(balResp.isSuccess());
        long istC2 = decodeUint256(extractReturnData(balResp.getResult()));
        long genesisIst = 10_000_000_000L / 3;
        assertEquals(genesisIst + 5000L, istC2,
                "C2 IST balance must increase by 5000 from the ERC-20 transfer in the block");
    }

    // =========================================================================
    // Test 3 – Fee-ordered block: high-fee tx executes first and affects state
    // =========================================================================

    @Test @Order(3)
    void feeOrderedBlockHighFeeTxExecutesFirst() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Simulate what the leader's greedy frontier would produce:
        // Client 1 pays gasPrice=10 (high fee) -> placed first in block
        // Client 0 pays gasPrice=1 (low fee) -> placed second in block
        ClientRequest highFeeTx = new ClientRequest(CLIENT_1, 1,
                clientAddr(CLIENT_2), 300L,
                30_000L, 10L, "", System.currentTimeMillis());

        ClientRequest lowFeeTx = new ClientRequest(CLIENT_0, 1,
                clientAddr(CLIENT_2), 100L,
                30_000L, 1L, "", System.currentTimeMillis());

        // Block ordered by fee (high first, as leader would produce)
        List<ClientRequest> blockTxs = List.of(highFeeTx, lowFeeTx);
        List<ClientResponse> responses = executeBlock(handler, net, blockTxs);

        assertTrue(responses.get(0).isSuccess(), "High-fee tx must succeed");
        assertTrue(responses.get(1).isSuccess(), "Low-fee tx must succeed");

        // Verify cumulative state
        long c2 = getBalance(state, clientAddr(CLIENT_2));
        assertEquals(GENESIS_NATIVE_BALANCE + 300 + 100, c2,
                "Client 2 receives value from both transactions in the block");

        // Verify different gas charges per gasPrice
        long c1 = getBalance(state, clientAddr(CLIENT_1));
        long c0 = getBalance(state, clientAddr(CLIENT_0));
        assertEquals(GENESIS_NATIVE_BALANCE - 300 - 21_000L * 10, c1,
                "Client 1 charged value + gas at gasPrice=10");
        assertEquals(GENESIS_NATIVE_BALANCE - 100 - 21_000L * 1, c0,
                "Client 0 charged value + gas at gasPrice=1");
    }

    // =========================================================================
    // Test 4 – One failing tx in block doesn't prevent others from executing
    // =========================================================================

    @Test @Order(4)
    void failingTxInBlockDoesNotPreventOthers() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Tx1: Valid native transfer
        ClientRequest validTx = new ClientRequest(CLIENT_0, 1,
                clientAddr(CLIENT_1), 100L,
                30_000L, 1L, "", System.currentTimeMillis());

        // Tx2: ERC-20 approve that will REVERT (non-zero to non-zero)
        // First set up a non-zero allowance
        String approve100Data = SEL_APPROVE + encodeAddress(clientAddr(CLIENT_1)) + encodeUint256(100L);
        ClientRequest setupApprove = new ClientRequest(CLIENT_1, 1,
                ISTCOIN_ADDRESS, 0L, 100_000L, 1L,
                approve100Data, System.currentTimeMillis());

        // Execute setup outside the block
        handler.execute(setupApprove);
        net.awaitNext(2000);

        // Now the block: valid transfer + approve that reverts (non-zero->non-zero)
        String approve50Data = SEL_APPROVE + encodeAddress(clientAddr(CLIENT_1)) + encodeUint256(50L);
        ClientRequest revertingTx = new ClientRequest(CLIENT_1, 2,
                ISTCOIN_ADDRESS, 0L, 50_000L, 1L,
                approve50Data, System.currentTimeMillis());

        // Tx3: Another valid native transfer
        ClientRequest validTx2 = new ClientRequest(CLIENT_2, 1,
                clientAddr(CLIENT_0), 75L,
                30_000L, 1L, "", System.currentTimeMillis());

        List<ClientRequest> blockTxs = List.of(validTx, revertingTx, validTx2);
        List<ClientResponse> responses = executeBlock(handler, net, blockTxs);

        assertTrue(responses.get(0).isSuccess(), "First valid tx must succeed");
        assertFalse(responses.get(1).isSuccess(), "Reverting approve must fail");
        assertTrue(responses.get(2).isSuccess(), "Third valid tx must still succeed");

        // State after block:
        // C0: 1M - 100(sent) + 75(received) - 21_000*1(gas) = 978_975
        // C1: paid gas for setup approve + gas for reverted approve (gasLimit*gasPrice = 50_000)
        // C2: 1M - 75(sent) - 21_000*1(gas)
        long c0 = getBalance(state, clientAddr(CLIENT_0));
        long c0Expected = GENESIS_NATIVE_BALANCE - 100 + 75 - 21_000L;
        assertEquals(c0Expected, c0,
                "C0 must reflect: -100(sent) +75(received) -21000(gas)");
    }

    // =========================================================================
    // Test 5 – Sequential nonces in a block from same client
    // =========================================================================

    @Test @Order(5)
    void sequentialNoncesFromSameClientInBlock() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Client 0 submits 3 transactions with nonces 1, 2, 3 in the same block
        List<ClientRequest> blockTxs = List.of(
                new ClientRequest(CLIENT_0, 1, clientAddr(CLIENT_1), 10L,
                        30_000L, 1L, "", System.currentTimeMillis()),
                new ClientRequest(CLIENT_0, 2, clientAddr(CLIENT_1), 20L,
                        30_000L, 1L, "", System.currentTimeMillis()),
                new ClientRequest(CLIENT_0, 3, clientAddr(CLIENT_1), 30L,
                        30_000L, 1L, "", System.currentTimeMillis())
        );

        List<ClientResponse> responses = executeBlock(handler, net, blockTxs);

        for (int i = 0; i < 3; i++) {
            assertTrue(responses.get(i).isSuccess(),
                    "Tx " + (i + 1) + " must succeed: " + responses.get(i).getResult());
        }

        long gasFee = 21_000L * 1L;

        // C0 sent 10+20+30=60, paid 3x gas
        long c0 = getBalance(state, clientAddr(CLIENT_0));
        assertEquals(GENESIS_NATIVE_BALANCE - 60 - 3 * gasFee, c0,
                "C0 must lose 60 (value) + 3 * gasFee after 3 txs in one block");

        // C1 received 60
        long c1 = getBalance(state, clientAddr(CLIENT_1));
        assertEquals(GENESIS_NATIVE_BALANCE + 60, c1,
                "C1 must gain 60 DepCoin from the 3 transfers in the block");
    }

    // =========================================================================
    // Test 6 – Non-negative balance invariant: client cannot overdraw mid-block
    // =========================================================================

    @Test @Order(6)
    void nonNegativeBalanceInvariantHoldsWithinBlock() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Client 0 starts with 1M DepCoin.
        // Upfront cost check: value + gasLimit * gasPrice must fit in balance.
        // Tx1: Send 960_000 (+ 30_000 gas ceiling = 990_000 upfront) -> succeeds
        //      After tx1: 1M - 960_000 - 21_000*1 = 19_000
        // Tx2: Try to send 960_000 again -> fails (insufficient balance)
        List<ClientRequest> blockTxs = List.of(
                new ClientRequest(CLIENT_0, 1, clientAddr(CLIENT_1), 960_000L,
                        30_000L, 1L, "", System.currentTimeMillis()),
                new ClientRequest(CLIENT_0, 2, clientAddr(CLIENT_1), 960_000L,
                        30_000L, 1L, "", System.currentTimeMillis())
        );

        List<ClientResponse> responses = executeBlock(handler, net, blockTxs);

        assertTrue(responses.get(0).isSuccess(), "First large transfer must succeed");
        assertFalse(responses.get(1).isSuccess(),
                "Second transfer must fail: client has insufficient balance after first tx in the block");

        // Balance must be non-negative
        long c0 = getBalance(state, clientAddr(CLIENT_0));
        assertTrue(c0 >= 0, "Balance must never go negative: " + c0);
    }
}
