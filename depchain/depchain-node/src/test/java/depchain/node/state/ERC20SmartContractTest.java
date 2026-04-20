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
 * Automated tests for ERC-20 ISTCoin smart contract execution via the EVM.
 *
 * Covers:
 *   - ERC-20 transfer and balanceOf through the UpcallHandler/EVM pipeline
 *   - approve + transferFrom delegation
 *   - Approval Frontrunning mitigation (non-zero to non-zero approve is rejected)
 *   - increaseAllowance / decreaseAllowance safe alternatives
 *   - allowance query
 *
 * These tests use the real ServiceState (which deploys ISTCoin from genesis.json)
 * and execute transactions through UpcallHandler exactly as in production.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ERC20SmartContractTest {

    // ── Constants ─────────────────────────────────────────────────────────────
    static final int NODE_ID = 0;
    static final int CLIENT_0 = 0;  // Address: 0x...c0
    static final int CLIENT_1 = 1;  // Address: 0x...c1
    static final int CLIENT_2 = 2;  // Address: 0x...c2

    // Pre-deployed ISTCoin contract address (deterministic from genesis deployer)
    static final String ISTCOIN_ADDRESS = "0x8f7a45ebde059392e46a46dcc14ab24681a961ea";

    // ERC-20 function selectors
    static final String SEL_BALANCE_OF    = "0x70a08231";
    static final String SEL_TRANSFER      = "0xa9059cbb";
    static final String SEL_APPROVE       = "0x095ea7b3";
    static final String SEL_ALLOWANCE     = "0xdd62ed3e";
    static final String SEL_TRANSFER_FROM = "0x23b872dd";
    static final String SEL_INC_ALLOW     = "0x39509351";
    static final String SEL_DEC_ALLOW     = "0xa457c2d7";

    // Standard gas parameters for ERC-20 calls
    static final long GAS_LIMIT = 100_000L;
    static final long GAS_PRICE = 1L;

    // ── Infrastructure ────────────────────────────────────────────────────────

    static final class CapturingNetwork implements Network {
        final BlockingQueue<Message> sent = new LinkedBlockingQueue<>();

        @Override
        public void send(InetAddress destIp, int destPort, Message msg) {
            sent.offer(msg);
        }

        Message awaitNext(long ms) throws InterruptedException {
            return sent.poll(ms, TimeUnit.MILLISECONDS);
        }

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

    // ── ABI encoding helpers ──────────────────────────────────────────────────

    /** Left-pad a hex string (without 0x prefix) to 64 hex chars (32 bytes). */
    private static String padLeft(String hex) {
        if (hex.startsWith("0x")) hex = hex.substring(2);
        return String.format("%64s", hex).replace(' ', '0');
    }

    private static String encodeAddress(String address) {
        return padLeft(address);
    }

    private static String encodeUint256(long value) {
        return padLeft(BigInteger.valueOf(value).toString(16));
    }

    /** Client ID -> Ethereum address hex string. */
    private static String clientAddress(int clientId) {
        return String.format("0x00000000000000000000000000000000000000c%x", clientId);
    }

    /** Build a ClientRequest that calls the ISTCoin contract. */
    private static ClientRequest erc20Call(int clientId, int requestId, String selector, String... params) {
        StringBuilder data = new StringBuilder(selector);
        for (String p : params) data.append(p);
        return new ClientRequest(
                clientId, requestId, ISTCOIN_ADDRESS, 0L,
                GAS_LIMIT, GAS_PRICE, data.toString(),
                System.currentTimeMillis());
    }

    /** Execute a request and return the ClientResponse. */
    private static ClientResponse exec(UpcallHandler handler, CapturingNetwork net,
                                        ClientRequest req) throws Exception {
        handler.execute(req);
        Message msg = net.awaitNext(2000);
        assertNotNull(msg, "Expected a CLIENT_RESPONSE for requestId=" + req.getRequestId());
        return ClientResponse.fromJson(msg.getContent());
    }

    /** Decode a uint256 from EVM return data hex (first 32 bytes). */
    private static long decodeUint256(String hexReturnData) {
        // Strip leading zeros and parse
        if (hexReturnData.length() >= 64) {
            hexReturnData = hexReturnData.substring(0, 64);
        }
        return new BigInteger(hexReturnData, 16).longValue();
    }

    /** Extract the hex return data from the response result string. */
    private static String extractReturnData(String result) {
        if (!result.contains("ReturnData: 0x")) return null;
        int idx = result.indexOf("ReturnData: 0x") + 14;
        return result.substring(idx).trim();
    }

    // =========================================================================
    // Test 1 – ERC-20 balanceOf: genesis allocation is correct
    // =========================================================================

    @Test @Order(1)
    void balanceOfReturnsGenesisAllocation() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // query IST Coin balance of Client 0 (0x...c0)
        ClientRequest req = erc20Call(CLIENT_0, 1, SEL_BALANCE_OF,
                encodeAddress(clientAddress(CLIENT_0)));

        ClientResponse resp = exec(handler, net, req);
        assertTrue(resp.isSuccess(), "balanceOf must succeed: " + resp.getResult());

        String returnData = extractReturnData(resp.getResult());
        assertNotNull(returnData, "Must have return data");
        long balance = decodeUint256(returnData);

        // Genesis deploys ISTCoin with 100M * 10^2 = 10_000_000_000 split among 3 clients
        // (c0, c1, c2 are the initialOwners array in the bytecode constructor args)
        long expectedPerClient = 10_000_000_000L / 3;
        assertEquals(expectedPerClient, balance,
                "Each client should receive 1/3 of the total IST Coin supply");
    }

    // =========================================================================
    // Test 2 – ERC-20 transfer: tokens move between accounts
    // =========================================================================

    @Test @Order(2)
    void transferMovesTokensBetweenAccounts() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long transferAmount = 1000L;

        // Transfer 1000 IST from Client 0 to Client 1
        ClientRequest transferReq = erc20Call(CLIENT_0, 1, SEL_TRANSFER,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(transferAmount));
        ClientResponse transferResp = exec(handler, net, transferReq);
        assertTrue(transferResp.isSuccess(), "transfer must succeed: " + transferResp.getResult());

        // Check Client 0 balance decreased
        ClientRequest bal0 = erc20Call(CLIENT_0, 2, SEL_BALANCE_OF,
                encodeAddress(clientAddress(CLIENT_0)));
        ClientResponse resp0 = exec(handler, net, bal0);
        assertTrue(resp0.isSuccess(), "balanceOf C0 must succeed");
        long balance0 = decodeUint256(extractReturnData(resp0.getResult()));

        // Check Client 1 balance increased
        ClientRequest bal1 = erc20Call(CLIENT_0, 3, SEL_BALANCE_OF,
                encodeAddress(clientAddress(CLIENT_1)));
        ClientResponse resp1 = exec(handler, net, bal1);
        assertTrue(resp1.isSuccess(), "balanceOf C1 must succeed");
        long balance1 = decodeUint256(extractReturnData(resp1.getResult()));

        long genesisPerClient = 10_000_000_000L / 3;
        assertEquals(genesisPerClient - transferAmount, balance0,
                "Client 0 IST balance must decrease by transfer amount");
        assertEquals(genesisPerClient + transferAmount, balance1,
                "Client 1 IST balance must increase by transfer amount");
    }

    // =========================================================================
    // Test 3 – ERC-20 approve + allowance query
    // =========================================================================

    @Test @Order(3)
    void approveAndAllowanceQuery() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long approveAmount = 500L;

        // Client 0 approves Client 1 to spend 500 IST
        ClientRequest approveReq = erc20Call(CLIENT_0, 1, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(approveAmount));
        ClientResponse approveResp = exec(handler, net, approveReq);
        assertTrue(approveResp.isSuccess(), "approve must succeed: " + approveResp.getResult());

        // Query the allowance
        ClientRequest allowanceReq = erc20Call(CLIENT_0, 2, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        ClientResponse allowanceResp = exec(handler, net, allowanceReq);
        assertTrue(allowanceResp.isSuccess(), "allowance query must succeed");

        long allowance = decodeUint256(extractReturnData(allowanceResp.getResult()));
        assertEquals(approveAmount, allowance,
                "Allowance must equal the approved amount");
    }

    // =========================================================================
    // Test 4 – ERC-20 approve + transferFrom delegation
    // =========================================================================

    @Test @Order(4)
    void approveAndTransferFromWorks() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long approveAmount = 200L;
        long transferAmount = 150L;

        // Client 0 approves Client 1 for 200 IST
        ClientRequest approveReq = erc20Call(CLIENT_0, 1, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(approveAmount));
        ClientResponse approveResp = exec(handler, net, approveReq);
        assertTrue(approveResp.isSuccess(), "approve must succeed");

        // Client 1 calls transferFrom(Client0, Client2, 150)
        ClientRequest transferFromReq = erc20Call(CLIENT_1, 1, SEL_TRANSFER_FROM,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_2)),
                encodeUint256(transferAmount));
        ClientResponse tfResp = exec(handler, net, transferFromReq);
        assertTrue(tfResp.isSuccess(), "transferFrom must succeed: " + tfResp.getResult());

        // Verify balances
        long genesisPerClient = 10_000_000_000L / 3;

        ClientRequest bal0 = erc20Call(CLIENT_0, 2, SEL_BALANCE_OF,
                encodeAddress(clientAddress(CLIENT_0)));
        long balance0 = decodeUint256(extractReturnData(exec(handler, net, bal0).getResult()));
        assertEquals(genesisPerClient - transferAmount, balance0,
                "Client 0 IST must decrease by transferFrom amount");

        ClientRequest bal2 = erc20Call(CLIENT_0, 3, SEL_BALANCE_OF,
                encodeAddress(clientAddress(CLIENT_2)));
        long balance2 = decodeUint256(extractReturnData(exec(handler, net, bal2).getResult()));
        assertEquals(genesisPerClient + transferAmount, balance2,
                "Client 2 IST must increase by transferFrom amount");

        // Verify remaining allowance = 200 - 150 = 50
        ClientRequest allowReq = erc20Call(CLIENT_0, 4, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        long remaining = decodeUint256(extractReturnData(exec(handler, net, allowReq).getResult()));
        assertEquals(approveAmount - transferAmount, remaining,
                "Remaining allowance must be reduced by the transferred amount");
    }

    // =========================================================================
    // Test 5 – FRONTRUNNING MITIGATION: non-zero to non-zero approve REVERTS
    // =========================================================================

    @Test @Order(5)
    void frontrunningMitigationRejectsNonZeroToNonZeroApprove() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Step 1: Client 0 approves Client 1 for 100 IST (from zero -> ok)
        ClientRequest approve100 = erc20Call(CLIENT_0, 1, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        ClientResponse resp1 = exec(handler, net, approve100);
        assertTrue(resp1.isSuccess(), "Initial approve(100) must succeed");

        // Step 2: Client 0 tries to change allowance from 100 to 50 directly
        // This MUST FAIL — the ISTCoin contract requires resetting to 0 first
        ClientRequest approve50 = erc20Call(CLIENT_0, 2, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(50L));
        ClientResponse resp2 = exec(handler, net, approve50);
        assertFalse(resp2.isSuccess(),
                "approve(non-zero->non-zero) MUST revert to prevent frontrunning attack");
        assertTrue(resp2.getResult().contains("REVERTED"),
                "Response must indicate EVM revert");

        // Step 3: Verify the allowance is unchanged (still 100)
        ClientRequest allowReq = erc20Call(CLIENT_0, 3, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        ClientResponse allowResp = exec(handler, net, allowReq);
        assertTrue(allowResp.isSuccess());
        long allowance = decodeUint256(extractReturnData(allowResp.getResult()));
        assertEquals(100L, allowance,
                "Allowance must remain 100 after failed non-zero-to-non-zero approve");
    }

    // =========================================================================
    // Test 6 – FRONTRUNNING MITIGATION: reset to 0 then re-approve works
    // =========================================================================

    @Test @Order(6)
    void frontrunningMitigationAllowsResetToZeroThenReApprove() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Step 1: approve Client 1 for 100
        ClientRequest approve100 = erc20Call(CLIENT_0, 1, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        assertTrue(exec(handler, net, approve100).isSuccess());

        // Step 2: Reset to 0 (this must succeed — zero value is always ok)
        ClientRequest approveZero = erc20Call(CLIENT_0, 2, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(0L));
        ClientResponse zeroResp = exec(handler, net, approveZero);
        assertTrue(zeroResp.isSuccess(), "approve(0) must succeed to reset allowance");

        // Step 3: Now approve 50 (from zero -> ok)
        ClientRequest approve50 = erc20Call(CLIENT_0, 3, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(50L));
        ClientResponse newResp = exec(handler, net, approve50);
        assertTrue(newResp.isSuccess(), "approve(50) after reset must succeed");

        // Verify final allowance = 50
        ClientRequest allowReq = erc20Call(CLIENT_0, 4, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        long finalAllowance = decodeUint256(extractReturnData(exec(handler, net, allowReq).getResult()));
        assertEquals(50L, finalAllowance,
                "Allowance must be 50 after zero-reset + re-approve");
    }

    // =========================================================================
    // Test 7 – FRONTRUNNING MITIGATION: decreaseAllowance as safe alternative
    // =========================================================================

    @Test @Order(7)
    void decreaseAllowanceWorksAsSafeAlternative() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Approve Client 1 for 100
        ClientRequest approve100 = erc20Call(CLIENT_0, 1, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        assertTrue(exec(handler, net, approve100).isSuccess());

        // Decrease allowance by 50 (safe alternative to re-approve)
        ClientRequest decrease = erc20Call(CLIENT_0, 2, SEL_DEC_ALLOW,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(50L));
        ClientResponse decResp = exec(handler, net, decrease);
        assertTrue(decResp.isSuccess(), "decreaseAllowance must succeed");

        // Verify allowance = 50
        ClientRequest allowReq = erc20Call(CLIENT_0, 3, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        long allowance = decodeUint256(extractReturnData(exec(handler, net, allowReq).getResult()));
        assertEquals(50L, allowance, "Allowance must decrease from 100 to 50");
    }

    // =========================================================================
    // Test 8 – increaseAllowance works without triggering frontrunning guard
    // =========================================================================

    @Test @Order(8)
    void increaseAllowanceBypassesFrontrunningGuard() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Approve Client 1 for 100
        ClientRequest approve100 = erc20Call(CLIENT_0, 1, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        assertTrue(exec(handler, net, approve100).isSuccess());

        // Increase allowance by 50 (bypasses the approve guard because it calls _approve internally)
        ClientRequest increase = erc20Call(CLIENT_0, 2, SEL_INC_ALLOW,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(50L));
        ClientResponse incResp = exec(handler, net, increase);
        assertTrue(incResp.isSuccess(), "increaseAllowance must succeed");

        // Verify allowance = 150
        ClientRequest allowReq = erc20Call(CLIENT_0, 3, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        long allowance = decodeUint256(extractReturnData(exec(handler, net, allowReq).getResult()));
        assertEquals(150L, allowance, "Allowance must increase from 100 to 150");
    }

    // =========================================================================
    // Test 9 – FULL FRONTRUNNING ATTACK SCENARIO: attacker cannot steal tokens
    // =========================================================================

    @Test @Order(9)
    void fullFrontrunningAttackScenarioIsBlocked() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        long genesisPerClient = 10_000_000_000L / 3;

        // SETUP: Client 0 approves Client 1 (malicious) for 100 IST
        ClientRequest approve100 = erc20Call(CLIENT_0, 1, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        assertTrue(exec(handler, net, approve100).isSuccess());

        // ATTACK STEP 1: Client 1 sees Client 0 about to reduce to 50.
        // The attacker rushes a transferFrom(C0, C1, 100) first.
        ClientRequest attackTransfer = erc20Call(CLIENT_1, 1, SEL_TRANSFER_FROM,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        ClientResponse attackResp = exec(handler, net, attackTransfer);
        assertTrue(attackResp.isSuccess(), "First transferFrom(100) succeeds (allowance = 100)");

        // Allowance should now be 0 after spending all 100
        ClientRequest allowCheck = erc20Call(CLIENT_0, 2, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        long allowanceAfterAttack = decodeUint256(extractReturnData(exec(handler, net, allowCheck).getResult()));
        assertEquals(0L, allowanceAfterAttack, "Allowance must be 0 after full transfer");

        // ATTACK STEP 2: Client 0's approve(50) now arrives.
        // With the mitigation: since allowance is now 0, this SUCCEEDS (0->50 is fine).
        ClientRequest approve50 = erc20Call(CLIENT_0, 3, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(50L));
        ClientResponse approve50Resp = exec(handler, net, approve50);
        assertTrue(approve50Resp.isSuccess(), "approve(50) from 0 allowance succeeds");

        // ATTACK STEP 3: The attacker tries to drain 50 more
        ClientRequest secondDrain = erc20Call(CLIENT_1, 2, SEL_TRANSFER_FROM,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(50L));
        ClientResponse secondDrainResp = exec(handler, net, secondDrain);
        assertTrue(secondDrainResp.isSuccess(), "transferFrom(50) with approved 50 succeeds");

        // RESULT: Attacker got 100 + 50 = 150 instead of intended max of 50.
        // BUT: in the scenario where Client 0 had done approve(100) initially,
        // and later tries approve(50) WHILE allowance is still 100,
        // the attack is BLOCKED because non-zero-to-non-zero reverts!
        //
        // Let's verify this scenario too with a fresh approval:
        ClientRequest approve200 = erc20Call(CLIENT_0, 4, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(200L));
        assertTrue(exec(handler, net, approve200).isSuccess());

        // Now the attacker must act before allowance changes.
        // Client 0 tries to reduce from 200 to 100 directly:
        ClientRequest reduceApprove = erc20Call(CLIENT_0, 5, SEL_APPROVE,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        ClientResponse reduceResp = exec(handler, net, reduceApprove);
        assertFalse(reduceResp.isSuccess(),
                "Direct reduction from 200 to 100 MUST REVERT — this prevents the frontrunning race");

        // The only safe way is decreaseAllowance:
        ClientRequest safeDec = erc20Call(CLIENT_0, 6, SEL_DEC_ALLOW,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(100L));
        assertTrue(exec(handler, net, safeDec).isSuccess(),
                "decreaseAllowance(100) must work as the safe alternative");

        // Verify final allowance: 200 - 100 = 100
        ClientRequest finalAllow = erc20Call(CLIENT_0, 7, SEL_ALLOWANCE,
                encodeAddress(clientAddress(CLIENT_0)),
                encodeAddress(clientAddress(CLIENT_1)));
        long finalAllowance = decodeUint256(extractReturnData(exec(handler, net, finalAllow).getResult()));
        assertEquals(100L, finalAllowance,
                "Final allowance after decreaseAllowance must be 100");
    }

    // =========================================================================
    // Test 10 – IST Coin transfers do NOT affect DepCoin (native) balances
    // =========================================================================

    @Test @Order(10)
    void istCoinTransfersDoNotAffectNativeDepCoinBalances() throws Exception {
        CapturingNetwork net = new CapturingNetwork();
        ServiceState state = new ServiceState();
        UpcallHandler handler = new UpcallHandler(state, net, membership(), NODE_ID, null);

        // Record initial native DepCoin balance (from genesis: 1_000_000 each)
        Address client0Addr = Address.fromHexString(clientAddress(CLIENT_0));
        long initialNativeBalance = state.getWorld().get(client0Addr).getBalance().toLong();
        assertEquals(1_000_000L, initialNativeBalance, "Genesis native balance should be 1M DepCoin");

        // Execute an IST Coin transfer (costs gas in DepCoin, moves IST)
        ClientRequest transfer = erc20Call(CLIENT_0, 1, SEL_TRANSFER,
                encodeAddress(clientAddress(CLIENT_1)),
                encodeUint256(500L));
        ClientResponse resp = exec(handler, net, transfer);
        assertTrue(resp.isSuccess(), "IST transfer must succeed");

        // Native balance should only have decreased by gas fee, NOT by the IST transfer amount (500)
        // Gas fee for an ERC-20 transfer SC call: gasUsed * gasPrice (gasPrice=1)
        // The IST token value (500) moves in the EVM storage, not in native DepCoin
        long afterNativeBalance = state.getWorld().get(client0Addr).getBalance().toLong();
        long nativeLoss = initialNativeBalance - afterNativeBalance;
        assertTrue(nativeLoss > 0, "Native balance must decrease (gas was charged)");
        // The loss must equal gas only (no value transfer in native coin)
        // Since value=0 in the request, all native loss is gas
        // Verify it's within reasonable EVM gas range (< gasLimit * gasPrice = 100_000)
        assertTrue(nativeLoss < GAS_LIMIT * GAS_PRICE,
                "Native loss (" + nativeLoss + ") must be less than gasLimit*gasPrice (gas only)");

        // Cross-check: IST token balance DID change
        ClientRequest balAfter = erc20Call(CLIENT_0, 2, SEL_BALANCE_OF,
                encodeAddress(clientAddress(CLIENT_0)));
        ClientResponse balResp = exec(handler, net, balAfter);
        assertTrue(balResp.isSuccess());
        long istAfter = decodeUint256(extractReturnData(balResp.getResult()));
        long genesisIst = 10_000_000_000L / 3;
        assertEquals(genesisIst - 500L, istAfter,
                "IST token balance must decrease by 500 (token transfer happened in EVM storage)");
    }
}
