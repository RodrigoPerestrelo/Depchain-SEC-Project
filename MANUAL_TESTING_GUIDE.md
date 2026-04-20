# Manual Testing Guide - DepChain (Stage 2)

This guide provides extensive manual testing procedures for the DepChain permissioned blockchain. It covers BFT consensus, the EVM execution, Native DepCoin transfers, the ERC-20 ISTCoin smart contract (with Frontrunning mitigations), the Fee Market (Greedy Frontier Algorithm), and deterministic block persistence.

## 🛠 Prerequisites & Initial Setup

1. **Clean and Build the project:**
   Always ensure a clean slate before starting a full test suite. This deletes old block files across all node directories.
   ```bash
   cd depchain
   mvn clean install
   ```

2. **Open 8 Terminals:** You will need multiple terminal windows to simulate the distributed network.
   - Terminals 1 to 4: Nodes (0, 1, 2, 3)
   - Terminals 5 to 7: Clients (0, 1, 2)

## 🧪 Test 1: Network Boot & Genesis Verification

**Objective:** Verify that nodes successfully boot, load the genesis state, deploy the ISTCoin ERC-20 contract, and establish BFT connections.

**Steps:**

1. **Start the 4 Nodes (in Terminals 1 to 4):**
   ```bash
   # Terminal 1
   cd depchain-node
   mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="0 ../config/nodes.json ../config/clients.json ../config/keys"

   # Terminal 2
   cd depchain-node
   mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="1 ../config/nodes.json ../config/clients.json ../config/keys"

   # Terminal 3
   cd depchain-node
   mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="2 ../config/nodes.json ../config/clients.json ../config/keys"

   # Terminal 4
   cd depchain-node
   mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="3 ../config/nodes.json ../config/clients.json ../config/keys"

   ```

2. **Expected Node Output:**
   - `Genesis: Funded account 0x... with 1000000 DepCoin`
   - `Genesis: ISTCoin deployed by System Account`
   - `[APL] Session established with /127.0.0.1:... ` (Indicates nodes are connected).

3. **Start Client 0 (Terminal 5):**
   ```bash
   cd depchain-client
   mvn exec:java -Dexec.mainClass="depchain.client.ClientApp" -Dexec.args="0 ../config/nodes.json ../config/clients.json ../config/keys"
   ```

## 🧪 Test 2: Native DepCoin & EVM Gas Deductions

**Objective:** Test direct transfers of the native cryptocurrency (DepCoin), ensure gas limits are respected, and verify that the consensus Leader receives the gas fees as a reward.

**Steps:**

1. In Client 0's menu, select **Option 1** (Transfer Native DepCoin).
2. Enter the details:
   - Destination: `0x00000000000000000000000000000000000000c1` (Client 1)
   - Amount: 500
   - Gas Limit: 25000
   - Gas Price: 2

3. Wait for the transaction to be committed. Check the node logs to see which Node was the Leader for this View (e.g., `LEADER [View X]`).

<!--4. In Client 0, select **Option 8** (Check Native DepCoin Balance) for your own address (`...c0`). **TAMALE** -->

**Expected Results:**

- **Client 0 Balance:** Should be `1000000 - 500 - (21000 * 2) = 957500` DepCoins. (21,000 is the fixed gas cost for native transfers).
- **Client 1 Balance:** Should be `1000000 + 500 = 1000500` DepCoins.

- **Block Persistence Check:**
  - Navigate to `depchain/config/blocks/node_0/` and open `block_1.json`.
  - Ensure the `"block_hash"` is identical across `node_1`, `node_2`, and `node_3` folders.
  - Look inside the `"state"` object. The Leader's address (`...aX`) should have its balance increased exactly by 42000 (from 1000000 to 1042000).

## 🧪 Test 3: ERC-20 Frontrunning Mitigation

**Objective:** Demonstrate that the custom ISTCoin contract successfully prevents the Approval Frontrunning attack by forcing allowance to zero or using safe modifiers.

**Steps:**

1. Start Client 1 (Terminal 6) and Client 2 (Terminal 7).

2. **Approve Setup:** In Client 0, select **Option 11** (Approve IST Coins).
   - Spender: `0x00000000000000000000000000000000000000c1` (Client 1)
   - Amount: 100
   - Gas Limit: 50000, Gas Price: 1

3. **The Attack Simulation (Failure):** Client 0 realizes 100 is too much and wants to change it to 50 using `approve(50)`.
   - In Client 0, select **Option 11** again.
   - Spender: `0x00000000000000000000000000000000000000c1` (Client 1)
   - Amount: 50
   - Gas Limit: 100000, Gas Price: 1
   - **Result:** Transaction FAILS (EVM Reverted). The contract explicitly rejects changing a non-zero allowance to another non-zero allowance to prevent frontrunning. Gas is still deducted as a penalty.

4. **The Safe Alternative:**
   - In Client 0, select **Option 13** (Decrease Allowance).
   - Spender: `0x00000000000000000000000000000000000000c1` (Client 1)
   - Amount: 50
   - Gas Limit: 100000, Gas Price: 1
   - **Result:** Transaction SUCCEEDS. Client 1 is now safely allowed to spend only 50 IST Coins.

## 🧪 Test 4: Mempool Dynamics (Block Gas Limit)

**Objective:** Prove that the blockchain dynamically stops accepting transactions into a block when the BLOCK_GAS_LIMIT (250,000) is reached, pushing leftovers to the next block without dropping them.

**Setup (Temporary Code Tweak):**

Since manual typing takes time, temporarily increase the consensus windows in `depchain-node/.../BasicHotStuff.java` and recompile (`mvn clean install`):

```java
private static final long BATCHING_PERIOD_MS = 15_000;
private static final long DEFAULT_VIEW_TIMEOUT_MS = 20_000;
```

**Steps:**

1. Restart the 4 nodes and 3 clients.
2. Within a 15-second window, quickly submit an ISTCoin Transfer (**Option 9**) from all 3 clients:
   - Client 0: Transfer 10 IST to Client 1.
     - Receiver: `0x00000000000000000000000000000000000000c1`
     - Amount: 10
     - Gas Limit: 100000, Gas Price: 1
   - Client 1: Transfer 10 IST to Client 2.
     - Receiver: `0x00000000000000000000000000000000000000c2`
     - Amount: 10
     - Gas Limit: 100000, Gas Price: 1
   - Client 2: Transfer 10 IST to Client 0.
     - Receiver: `0x00000000000000000000000000000000000000c0`
     - Amount: 10
     - Gas Limit: 100000, Gas Price: 1

**Expected Results:**

- **Block 1** (`block_1.json`): Will contain exactly 2 transactions. The total gas limit requested (200,000) fits under the 250,000 threshold.
- **Block 2** (`block_2.json`): Will be generated in the subsequent consensus view and will contain the 1 transaction that was deferred.
- Two clients will receive their CommitProof immediately, while the third will receive it a few seconds later.

## 🧪 Test 5: Fee Market & Greedy Algorithm

**Objective:** Verify that the Leader acts selfishly (Greedy Approach), ordering transactions by highest gasPrice to maximize profits.

**Steps (Using the 15-second batching window):**

Using the 3 Clients, quickly submit three Native DepCoin Transfers (**Option 1**) to any destination, but vary the Gas Price:

- Client 1: Transfer 1 DepCoin to Client 2.
  - Receiver: `0x00000000000000000000000000000000000000c2`
  - Amount: 1
  - Gas Limit: 50000, Gas Price: 10 (Low)
- Client 2: Transfer 1 DepCoin to Client 0.
  - Receiver: `0x00000000000000000000000000000000000000c0`
  - Amount: 1
  - Gas Limit: 50000, Gas Price: 80 (High)
- Client 0: Transfer 1 DepCoin to Client 1.
  - Receiver: `0x00000000000000000000000000000000000000c1`
  - Amount: 1
  - Gas Limit: 50000, Gas Price: 30 (Medium)

**Expected Results:**

Open the resulting `block_X.json` file. Check the `"transactions"` array. The system **MUST** have reordered them strictly by profitability:

1. Client 2 (Fee: 80)
2. Client 0 (Fee: 30)
3. Client 1 (Fee: 10)

## 🧪 Test 6: BFT Catch-Up / Synchronization

**Objective:** Prove that a temporarily disconnected (or delayed) node can recover missing blocks using the BlockFetchRequest mechanism.

**Steps (Revert the Code Tweak first):**

1. Change `BATCHING_PERIOD_MS` back to 2,000 and `DEFAULT_VIEW_TIMEOUT_MS` to 4,000. Rebuild and restart the network.

2. **Kill Node 3:** Go to Terminal 4 and stop the process (Ctrl+C).

3. **Advance the Chain:** With Node 3 offline, use Client 0 to submit 3 separate Native DepCoin Transfers (**Option 1**):
   - Transfer 1: Receiver: `0x00000000000000000000000000000000000000c1`, Amount: 1, Gas Limit: 21000, Gas Price: 1
   - Transfer 2: Receiver: `0x00000000000000000000000000000000000000c1`, Amount: 1, Gas Limit: 21000, Gas Price: 1
   - Transfer 3: Receiver: `0x00000000000000000000000000000000000000c1`, Amount: 1, Gas Limit: 21000, Gas Price: 1
   - The network will continue to reach consensus because 3 nodes are alive ($N = 3f+1$).

4. **Restart Node 3:** Run the Maven command in Terminal 4 again.

5. **Trigger Catch-Up:** Submit one final transaction using Client 0 (**Option 1**):
   - Receiver: `0x00000000000000000000000000000000000000c1`, Amount: 1, Gas Limit: 21000, Gas Price: 1

**Expected Results:**

- Node 3's terminal will show a log indicating a View Mismatch or that it is fetching blocks from peers (`FETCH_BLOCKS_REQ`).
- Check Node 3's persistence folder (`config/blocks/node_3/`). The missing blocks (1, 2, and 3) will be successfully written to disk, matching the hashes of the other nodes exactly.
- **Note for Evaluators:** The system's determinism can be verified at any stage by ensuring that `block_<height>.json` files have the exact same `block_hash` value across all `node_<id>` directories.
