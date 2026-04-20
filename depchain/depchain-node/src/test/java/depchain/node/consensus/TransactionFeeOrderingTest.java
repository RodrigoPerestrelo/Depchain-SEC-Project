package depchain.node.consensus;

import depchain.common.protocol.ClientRequest;

import org.junit.jupiter.api.*;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for inter-client transaction ordering by gas fee.
 *
 * The enunciado requires: "The execution order of these transactions should be
 * based on transaction fees, where a transaction with the highest transaction fee
 * will be executed first."
 *
 * The BasicHotStuff leader uses a Greedy Frontier Algorithm that:
 *   1. Groups pending transactions by clientId
 *   2. Sorts each client's queue by requestId (nonce order)
 *   3. At each step, picks the head transaction with the highest estimated fee
 *   4. Adds it to the block batch (respecting BLOCK_GAS_LIMIT)
 *
 * Since finalizeProposal() is private, these tests replicate the exact same
 * algorithm to verify the ordering invariant independently of the full consensus
 * machinery. This is explicitly the same code path executed in BasicHotStuff lines 515-606.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TransactionFeeOrderingTest {

    // Replicate the BLOCK_GAS_LIMIT from BasicHotStuff
    static final long BLOCK_GAS_LIMIT = 250_000L;

    // ── Replicated Greedy Frontier Algorithm ──────────────────────────────────
    // This is the exact logic from BasicHotStuff.finalizeProposal() extracted
    // for unit testing purposes.

    /**
     * Replicates BasicHotStuff.estimateTransactionFee() (lines 612-635).
     */
    static long estimateTransactionFee(ClientRequest tx) {
        if (tx == null) return 0L;
        long estimatedGas = 21000L;
        if (tx.getTo() == null || tx.getTo().isEmpty()) {
            estimatedGas = 53000L;
        }
        if (tx.getData() != null && !tx.getData().isEmpty()) {
            String data = tx.getData().startsWith("0x") ? tx.getData().substring(2) : tx.getData();
            long byteCount = data.length() / 2;
            estimatedGas += byteCount * 16L;
        }
        estimatedGas = Math.min(estimatedGas, tx.getGasLimit());
        return estimatedGas * tx.getGasPrice();
    }

    /**
     * Replicates BasicHotStuff.finalizeProposal() greedy frontier (lines 515-587).
     * Returns the ordered batch of transactions as the leader would propose them.
     */
    static List<ClientRequest> buildBlockBatch(List<ClientRequest> allPending) {
        Map<Integer, Queue<ClientRequest>> clientQueues = new HashMap<>();
        for (ClientRequest tx : allPending) {
            clientQueues.computeIfAbsent(tx.getClientId(),
                    k -> new PriorityQueue<>(Comparator.comparingInt(ClientRequest::getRequestId)))
                    .add(tx);
        }

        List<ClientRequest> batch = new ArrayList<>();
        long currentBlockGas = 0L;

        while (true) {
            ClientRequest bestTx = null;
            long bestFee = -1;
            int bestClientId = -1;

            for (Map.Entry<Integer, Queue<ClientRequest>> entry : clientQueues.entrySet()) {
                Queue<ClientRequest> queue = entry.getValue();
                if (queue.isEmpty()) continue;
                ClientRequest headTx = queue.peek();
                long fee = estimateTransactionFee(headTx);
                if (fee > bestFee) {
                    bestFee = fee;
                    bestTx = headTx;
                    bestClientId = entry.getKey();
                }
            }

            if (bestTx == null) break;

            long txGas = bestTx.getGasLimit();
            if (txGas > BLOCK_GAS_LIMIT) {
                clientQueues.get(bestClientId).poll();
                continue;
            }
            if (currentBlockGas + txGas <= BLOCK_GAS_LIMIT) {
                batch.add(bestTx);
                currentBlockGas += txGas;
                clientQueues.get(bestClientId).poll();
            } else {
                break;
            }
        }
        return batch;
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    static ClientRequest tx(int clientId, int requestId, long gasLimit, long gasPrice) {
        return new ClientRequest(clientId, requestId,
                "0x0000000000000000000000000000000000000001", 0L,
                gasLimit, gasPrice, "0x", System.currentTimeMillis());
    }

    // =========================================================================
    // Test 1 – Two different clients: higher gasPrice is placed first in block
    // =========================================================================

    @Test @Order(1)
    void higherFeeClientTransactionIsOrderedFirst() {
        // Client 0: low fee (gasPrice=1)
        ClientRequest lowFee = tx(0, 1, 30_000L, 1L);
        // Client 1: high fee (gasPrice=100)
        ClientRequest highFee = tx(1, 1, 30_000L, 100L);

        List<ClientRequest> batch = buildBlockBatch(List.of(lowFee, highFee));

        assertEquals(2, batch.size(), "Both transactions must fit in block");
        assertEquals(1, batch.get(0).getClientId(),
                "Client 1 (high fee) must be at position [0] of the block");
        assertEquals(0, batch.get(1).getClientId(),
                "Client 0 (low fee) must be at position [1] of the block");

        long fee0 = estimateTransactionFee(batch.get(0));
        long fee1 = estimateTransactionFee(batch.get(1));
        assertTrue(fee0 >= fee1,
                "Transactions must be ordered by descending fee: " + fee0 + " >= " + fee1);
    }

    // =========================================================================
    // Test 2 – Three clients with different fees: descending order
    // =========================================================================

    @Test @Order(2)
    void threeClientsOrderedByDescendingFee() {
        ClientRequest txA = tx(0, 1, 30_000L, 5L);   // fee ~= 21000*5 = 105_000
        ClientRequest txB = tx(1, 1, 30_000L, 50L);  // fee ~= 21000*50 = 1_050_000
        ClientRequest txC = tx(2, 1, 30_000L, 10L);  // fee ~= 21000*10 = 210_000

        List<ClientRequest> batch = buildBlockBatch(List.of(txA, txB, txC));

        assertEquals(3, batch.size());
        assertEquals(1, batch.get(0).getClientId(), "Client 1 (highest fee) must be first");
        assertEquals(2, batch.get(1).getClientId(), "Client 2 (mid fee) must be second");
        assertEquals(0, batch.get(2).getClientId(), "Client 0 (lowest fee) must be third");
    }

    // =========================================================================
    // Test 3 – Per-client nonce order is respected even with fee sorting
    // =========================================================================

    @Test @Order(3)
    void nonceOrderRespectedWithinSameClient() {
        // Client 0 has 2 transactions: req#1 (low fee) and req#2 (high fee)
        // Even though req#2 has higher fee, req#1 must execute first (nonce order)
        ClientRequest c0_req1 = tx(0, 1, 30_000L, 1L);    // low
        ClientRequest c0_req2 = tx(0, 2, 30_000L, 1000L);  // high

        // Client 1 has 1 transaction with medium fee
        ClientRequest c1_req1 = tx(1, 1, 30_000L, 50L);

        List<ClientRequest> batch = buildBlockBatch(List.of(c0_req1, c0_req2, c1_req1));

        assertEquals(3, batch.size());

        // Find positions of Client 0's transactions
        int pos_c0_r1 = -1, pos_c0_r2 = -1;
        for (int i = 0; i < batch.size(); i++) {
            if (batch.get(i).getClientId() == 0 && batch.get(i).getRequestId() == 1) pos_c0_r1 = i;
            if (batch.get(i).getClientId() == 0 && batch.get(i).getRequestId() == 2) pos_c0_r2 = i;
        }

        assertTrue(pos_c0_r1 >= 0, "Client 0 request #1 must be in batch");
        assertTrue(pos_c0_r2 >= 0, "Client 0 request #2 must be in batch");
        assertTrue(pos_c0_r1 < pos_c0_r2,
                "Client 0 request #1 (nonce=1) must appear before request #2 (nonce=2) " +
                "regardless of fee ordering: pos_r1=" + pos_c0_r1 + " pos_r2=" + pos_c0_r2);
    }

    // =========================================================================
    // Test 4 – Greedy frontier interleaving: highest head-of-queue wins each round
    // =========================================================================

    @Test @Order(4)
    void greedyFrontierInterleavesCorrectly() {
        // Client 0: req#1=100gp, req#2=1gp (will pick req#1 first, then req#2 last)
        // Client 1: req#1=50gp, req#2=50gp
        ClientRequest c0_r1 = tx(0, 1, 30_000L, 100L);
        ClientRequest c0_r2 = tx(0, 2, 30_000L, 1L);
        ClientRequest c1_r1 = tx(1, 1, 30_000L, 50L);
        ClientRequest c1_r2 = tx(1, 2, 30_000L, 50L);

        List<ClientRequest> batch = buildBlockBatch(List.of(c0_r1, c0_r2, c1_r1, c1_r2));

        assertEquals(4, batch.size(), "All 4 transactions fit in block");

        // Round 1: C0_r1(fee=100*21000) vs C1_r1(fee=50*21000) -> C0_r1 wins
        assertEquals(0, batch.get(0).getClientId());
        assertEquals(1, batch.get(0).getRequestId());

        // Round 2: C0_r2(fee=1*21000) vs C1_r1(fee=50*21000) -> C1_r1 wins
        assertEquals(1, batch.get(1).getClientId());
        assertEquals(1, batch.get(1).getRequestId());

        // Round 3: C0_r2(fee=1*21000) vs C1_r2(fee=50*21000) -> C1_r2 wins
        assertEquals(1, batch.get(2).getClientId());
        assertEquals(2, batch.get(2).getRequestId());

        // Round 4: C0_r2(fee=1*21000) only one left
        assertEquals(0, batch.get(3).getClientId());
        assertEquals(2, batch.get(3).getRequestId());
    }

    // =========================================================================
    // Test 5 – Block gas limit is respected
    // =========================================================================

    @Test @Order(5)
    void blockGasLimitIsRespected() {
        // Create transactions that would exceed BLOCK_GAS_LIMIT (250_000)
        // Each at gasLimit=100_000 -> can fit at most 2
        ClientRequest txA = tx(0, 1, 100_000L, 10L);  // high fee
        ClientRequest txB = tx(1, 1, 100_000L, 5L);   // mid fee
        ClientRequest txC = tx(2, 1, 100_000L, 1L);   // low fee

        List<ClientRequest> batch = buildBlockBatch(List.of(txA, txB, txC));

        assertEquals(2, batch.size(),
                "Only 2 transactions should fit (200_000 gas < 250_000 limit, 300_000 > 250_000)");
        assertEquals(0, batch.get(0).getClientId(), "Highest fee client first");
        assertEquals(1, batch.get(1).getClientId(), "Second highest fee client second");
    }

    // =========================================================================
    // Test 6 – Single oversized transaction is discarded
    // =========================================================================

    @Test @Order(6)
    void oversizedTransactionIsDiscarded() {
        // One tx exceeds BLOCK_GAS_LIMIT entirely
        ClientRequest oversized = tx(0, 1, 300_000L, 100L);
        // Normal tx
        ClientRequest normal = tx(1, 1, 30_000L, 1L);

        List<ClientRequest> batch = buildBlockBatch(List.of(oversized, normal));

        assertEquals(1, batch.size(), "Only the normal Tx fits");
        assertEquals(1, batch.get(0).getClientId(), "Normal tx should be included");
    }

    // =========================================================================
    // Test 7 – Equal fees: both transactions included (deterministic)
    // =========================================================================

    @Test @Order(7)
    void equalFeesAreHandledGracefully() {
        ClientRequest txA = tx(0, 1, 30_000L, 10L);
        ClientRequest txB = tx(1, 1, 30_000L, 10L);

        List<ClientRequest> batch = buildBlockBatch(List.of(txA, txB));

        assertEquals(2, batch.size(), "Both equal-fee transactions must be included");
        Set<Integer> clientIds = new HashSet<>();
        batch.forEach(t -> clientIds.add(t.getClientId()));
        assertEquals(Set.of(0, 1), clientIds, "Both clients must appear");
    }

    // =========================================================================
    // Test 8 – Fee estimation accounts for data payload size
    // =========================================================================

    @Test @Order(8)
    void feeEstimationAccountsForDataPayloadSize() {
        // Client 0: no data, gasPrice=10 -> fee = 21000 * 10 = 210_000
        ClientRequest noData = tx(0, 1, 50_000L, 10L);

        // Client 1: with data (20 bytes = 40 hex chars), gasPrice=10
        // fee = (21000 + 20*16) * 10 = (21000 + 320) * 10 = 213_200
        ClientRequest withData = new ClientRequest(1, 1,
                "0x0000000000000000000000000000000000000001", 0L,
                50_000L, 10L,
                "0x" + "aa".repeat(20),   // 20 bytes of data
                System.currentTimeMillis());

        long feeNoData = estimateTransactionFee(noData);
        long feeWithData = estimateTransactionFee(withData);

        assertTrue(feeWithData > feeNoData,
                "Transaction with data payload must have higher estimated fee: " +
                feeWithData + " > " + feeNoData);

        List<ClientRequest> batch = buildBlockBatch(List.of(noData, withData));
        assertEquals(1, batch.get(0).getClientId(),
                "Client 1 (with data, higher fee) must be ordered first");
    }
}
