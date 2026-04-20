# DepChain — Byzantine Fault-Tolerant Blockchain

DepChain is a permissioned (closed membership) blockchain system with high dependability guarantees. It implements the **Basic HotStuff** consensus protocol (Abraham et al., 2018), tolerating up to **f Byzantine faults** in a network of **n = 3f + 1** nodes, using threshold signatures for quorum certificates and authenticated perfect links for secure communication.

The system features a native cryptocurrency (**DepCoin**), an EVM-based smart contract execution engine powered by **Hyperledger Besu**, and a pre-deployed ERC-20 token (**IST Coin**) with built-in protection against Approval Frontrunning attacks.

## Prerequisites

- **Java 17** or later
- **Apache Maven 3.8+**

## Project Structure

```
depchain/
├── pom.xml                        # Parent Maven POM (multi-module)
├── threshsig/                     # Threshold signature library (Shoup's scheme)
├── depchain-common/               # Shared networking, crypto, and protocol classes
├── depchain-node/                 # Blockchain node (consensus, EVM execution, state)
├── depchain-client/               # Client library and interactive CLI
├── smart-contracts/               # Solidity source and compiled EVM bytecode
│   ├── ISTCoin.sol                # ERC-20 token with frontrunning mitigation
│   ├── ISTCoin.bytecode           # Deployment bytecode (constructor + runtime)
│   └── ISTCoin.runtime            # Runtime-only bytecode
└── config/                        # Key generation, membership, and chain data
    ├── GenerateKeys.java
    ├── nodes.json                 # Static membership (4 nodes)
    ├── clients.json               # Static membership (3 clients)
    ├── genesis.json               # Genesis block (initial state + contract deploy)
    ├── keys/                      # Generated cryptographic key material
    └── blocks/                    # Persisted blocks per node (created at runtime)
```

**Module dependencies:** `threshsig` <- `depchain-common` <- `depchain-node` / `depchain-client` / `config`

## Build

```bash
cd depchain
mvn clean install -DskipTests
```

## Key Generation

Before running the system for the first time, generate all cryptographic key material (ECDSA key pairs + threshold key shares):

```bash
cd depchain/config
mvn exec:java -Dexec.mainClass="depchain.config.GenerateKeys" -Dexec.args="keys 3 4 3"
```

Arguments: `keys` = output directory, `3` = threshold (k), `4` = total nodes (l), `3` = number of clients.

This writes inside `config/keys/`:

| File | Description |
|------|-------------|
| `node0.pub` ... `node6.pub` | ECDSA public keys (nodes 0-3, clients 4-6) |
| `node0.priv` ... `node6.priv` | ECDSA private keys |
| `node0.keyshare` ... `node3.keyshare` | Threshold key shares |
| `groupkey.properties` | Shared threshold group key |

> **Important:** If you regenerate keys, every node and client must use the new set. Never mix old and new key files.

## Running the System (Demo)

The default configuration runs **4 nodes** (f=1, quorum = 2f+1 = 3) and up to **3 clients**. Each entity must be started in a separate terminal.

### Start the 4 Nodes

Each node must be run from inside `depchain/depchain-node/`:

```bash
# Terminal 1 — Node 0
cd depchain/depchain-node
mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="0 ../config/nodes.json ../config/clients.json ../config/keys"

# Terminal 2 — Node 1 (initial leader for view 1)
cd depchain/depchain-node
mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="1 ../config/nodes.json ../config/clients.json ../config/keys"

# Terminal 3 — Node 2
cd depchain/depchain-node
mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="2 ../config/nodes.json ../config/clients.json ../config/keys"

# Terminal 4 — Node 3
cd depchain/depchain-node
mvn exec:java -Dexec.mainClass="depchain.node.core.BlockchainMember" -Dexec.args="3 ../config/nodes.json ../config/clients.json ../config/keys"
```

Wait for all four nodes to be running before starting any client. On boot, each node loads the genesis block, pre-funds all accounts with 1,000,000 DepCoin, and deploys the ISTCoin ERC-20 contract via EVM execution.

### Start Clients

Up to 3 clients can be started (IDs 0, 1, 2):

```bash
# Terminal 5 — Client 0
cd depchain/depchain-client
mvn exec:java -Dexec.mainClass="depchain.client.ClientApp" -Dexec.args="0 ../config/nodes.json ../config/clients.json ../config/keys"

# Terminal 6 — Client 1
cd depchain/depchain-client
mvn exec:java -Dexec.mainClass="depchain.client.ClientApp" -Dexec.args="1 ../config/nodes.json ../config/clients.json ../config/keys"

# Terminal 7 — Client 2
cd depchain/depchain-client
mvn exec:java -Dexec.mainClass="depchain.client.ClientApp" -Dexec.args="2 ../config/nodes.json ../config/clients.json ../config/keys"
```

### Client Menu

Once a client starts, an interactive menu appears with the following options:

| # | Operation | Description |
|---|-----------|-------------|
| 1 | Transfer DepCoin | Send native cryptocurrency between accounts |
| 2 | Check Native Balance | Query DepCoin balance of any account |
| 3-6 | ERC-20 Read | Name, Symbol, Decimals, Total Supply |
| 7 | Balance Of | Query IST Coin balance of an account |
| 8 | Allowance | Check ERC-20 spending allowance |
| 9 | Transfer (IST) | Transfer IST Coins to another account |
| 10 | Transfer From | Delegated transfer using allowance |
| 11 | Approve | Set spending allowance (frontrunning-safe) |
| 12 | Increase Allowance | Safely increase an existing allowance |
| 13 | Decrease Allowance | Safely decrease an existing allowance |

Each transaction prompts for **Gas Limit** and **Gas Price** parameters. The transaction fee is calculated as `min(gasPrice * gasLimit, gasPrice * gasUsed)`.

## System Design

### Genesis Block

The system starts with a genesis block (`config/genesis.json`) that:
- Pre-funds 8 accounts (1 system, 4 nodes, 3 clients) with 1,000,000 DepCoin each
- Deploys the ISTCoin ERC-20 smart contract via a contract creation transaction
- Distributes 100,000,000 IST Coins (with 2 decimals) equally among the 3 client accounts

### Native Cryptocurrency — DepCoin

Accounts can transfer DepCoin between each other. Every transaction incurs a gas fee (in DepCoin) that is awarded to the consensus leader (miner). Balances are enforced to be non-negative.

### ERC-20 Token — IST Coin

A custom ERC-20 token (`ISTCoin.sol`) deployed in the genesis block. It is named "IST Coin" (symbol: IST) with 2 decimals and a total supply of 100 million units. The contract includes **Approval Frontrunning mitigation**: `approve()` is overridden to reject non-zero-to-non-zero allowance changes, forcing users to reset to 0 first or use the safe `increaseAllowance()` / `decreaseAllowance()` alternatives.

### Gas Mechanism

Every transaction has a fee calculated as: `min(gas_price * gas_limit, gas_price * gas_used)`.

- **Native transfers**: Fixed intrinsic gas of 21,000 units
- **Smart contract calls**: Actual gas used as reported by the EVM
- **Reverted transactions**: Charged `gas_limit * gas_price` as a penalty (gas is not refunded)
- **Balance checks**: Charged 21,000 intrinsic gas
- The consensus leader collects all gas fees as miner rewards

### Transaction Ordering — Greedy Frontier Algorithm

The leader orders transactions within a block by descending estimated fee (maximizing miner profit) while respecting per-client nonce order. A block gas limit of **250,000** caps the total gas in a single block; excess transactions are deferred to the next block.

### Block Persistence

Each committed block is persisted as a JSON file (`config/blocks/node_X/block_N.json`) containing:
- `block_hash` (SHA-256)
- `previous_block_hash` (chain link)
- `transactions` (ordered list of signed transactions)
- `state` (full world state snapshot: all account balances and nonces)

### Block Recovery

Nodes that miss blocks (e.g., due to temporary disconnection) can catch up using the `FETCH_BLOCKS_REQ` / `FETCH_BLOCKS_RESP` protocol, recovering missing blocks from peers with quorum validation.

### EVM Execution

Smart contracts are executed using the **Hyperledger Besu** EVM (Cancun fork) embedded in each node. The execution engine supports:
- Contract deployment (constructor execution)
- Function calls with ABI-encoded data
- World state management via Besu's `SimpleWorld`
- Two-layer state updates: fees/nonces on the outer layer, EVM sandbox on the inner layer (reverted on failure while still charging gas)

## Running the Tests

All automated tests are self-contained: they generate their own keys in temporary directories and use an in-memory message bus (no real UDP required, no manual node startup needed).

```bash
cd depchain
mvn test
```

To run individual test modules:

```bash
mvn test -pl depchain-common      # Networking and crypto tests
mvn test -pl depchain-node        # Consensus, state, and EVM tests
mvn test -pl depchain-client      # Client integration tests
mvn test -pl threshsig            # Threshold signature tests
```

### Test Suite Summary

The test suite contains **88 tests** across **19 test classes** in 4 modules, covering consensus correctness, Byzantine fault tolerance, EVM execution, gas mechanics, ERC-20 operations, client protocol compliance, and threshold cryptography.

#### ERC-20 Smart Contract — `ERC20SmartContractTest` (10 tests)

Tests for the ISTCoin ERC-20 contract execution via the Besu EVM:

| Test | What it demonstrates |
|------|---------------------|
| `balanceOfReturnsGenesisAllocation` | Returns correct genesis allocation |
| `transferMovesTokensBetweenAccounts` | Moves IST tokens between accounts |
| `approveAndAllowanceQuery` | Approval and allowance query work correctly |
| `approveAndTransferFromWorks` | Delegated transfer via allowance |
| `frontrunningMitigationRejectsNonZeroToNonZeroApprove` | Non-zero-to-non-zero approve is rejected (EVM revert) |
| `frontrunningMitigationAllowsResetToZeroThenReApprove` | Setting allowance to 0 first, then to a new value succeeds |
| `decreaseAllowanceWorksAsSafeAlternative` | Safe alternative to reduce allowance |
| `increaseAllowanceBypassesFrontrunningGuard` | Safe alternative to increase allowance |
| `fullFrontrunningAttackScenarioIsBlocked` | Complete attack scenario is blocked |
| `istCoinTransfersDoNotAffectNativeDepCoinBalances` | IST transfers do not affect native DepCoin balances |

#### Gas Mechanism — `GasDeductionTest` (7 tests)

Tests for correct gas fee calculation and deduction:

| Test | What it demonstrates |
|------|---------------------|
| `nativeTransferChargesExactGasFee` | Charges 21,000 * gasPrice |
| `minerReceivesExactGasFeeReward` | Leader receives exact gas fee |
| `outOfGasChargesGasLimitTimesGasPrice` | Charges gasLimit * gasPrice as penalty |
| `smartContractCallChargesActualGasUsed` | Charges actual gas used (less than gasLimit) |
| `revertedSmartContractCallChargesFullGasLimit` | Charges full gasLimit * gasPrice on revert |
| `gasFeeConservation_SenderLossEqualsMinerGain` | Sender loss = receiver gain + miner gain |
| `nativeBalanceCheckChargesIntrinsicGas` | NATIVE_BALANCE charges intrinsic gas |

#### Multi-Transaction Blocks — `MultiTransactionBlockTest` (6 tests)

Tests for correct execution of multiple transactions within a single block:

| Test | What it demonstrates |
|------|---------------------|
| `threeNativeTransfersInOneBlockCumulativeState` | Three native transfers update balances correctly |
| `mixedNativeAndERC20TransactionsInOneBlock` | Native + ERC-20 operations coexist in one block |
| `feeOrderedBlockHighFeeTxExecutesFirst` | Transactions are executed in fee-descending order |
| `failingTxInBlockDoesNotPreventOthers` | A failing transaction does not prevent others from executing |
| `sequentialNoncesFromSameClientInBlock` | Same-client nonces are enforced within a block |
| `nonNegativeBalanceInvariantHoldsWithinBlock` | Balances remain non-negative mid-block |

#### Transaction Fee Ordering — `TransactionFeeOrderingTest` (8 tests)

Tests for the Greedy Frontier Algorithm:

| Test | What it demonstrates |
|------|---------------------|
| `higherFeeClientTransactionIsOrderedFirst` | Transactions ordered by descending estimated fee |
| `threeClientsOrderedByDescendingFee` | Multi-client ordering by fee |
| `nonceOrderRespectedWithinSameClient` | Per-client nonce order is preserved |
| `greedyFrontierInterleavesCorrectly` | Interleaving across clients respects both fee and nonce |
| `blockGasLimitIsRespected` | Transactions exceeding 250,000 gas cap are deferred |
| `oversizedTransactionIsDiscarded` | A single transaction exceeding the block limit is discarded |
| `equalFeesAreHandledGracefully` | Graceful handling of same-fee transactions |
| `feeEstimationAccountsForDataPayloadSize` | Fee estimation accounts for calldata size (16 gas per byte) |

#### Consensus Correctness — `HotStuffClusterTest` (5 tests)

End-to-end tests running a 4-node cluster with real threshold signatures over an in-memory bus:

| Test | What it demonstrates |
|------|---------------------|
| `happyPath` | Normal single-command consensus decision (all 4 nodes agree) |
| `multipleSequentialCommands` | Three consecutive decisions are applied in correct order |
| `oneNodeCrash` | One node goes offline; the remaining 3 still form a quorum and decide |
| `leaderFailureTriggerViewChange` | Leader is down; view-timeout fires, new leader completes consensus |
| `clientResponseDeliveredAfterDecision` | After consensus, at least 2f+1 `CLIENT_RESPONSE` messages are delivered |

#### Byzantine Behavior Detection — `ByzantineBehaviorTest` (6 tests)

Tests that exercise safety invariants against malicious behavior:

| Test | Threat addressed |
|------|-----------------|
| `safetyVoteOncePerPhase` | Prevents vote amplification by enforcing one vote per phase |
| `safetyRejectConflictingBlock` | Rejects conflicting blocks with weaker QC (prevents forks) |
| `corruptedSignatureDoesNotBlockLeader` | Garbage signatures are handled; consensus proceeds with valid votes |
| `byzantineLeaderFabricatesCommand` | Fabricated commands are rejected; view-timeout triggers honest leader |
| `replayedClientRequestRemainsValidInConsensusHarness` | Replayed valid request is handled correctly at consensus level |
| `twoClientsConcurrentThenByzantineReplayIsRejected` | Two concurrent clients decide; subsequent Byzantine replay is rejected |

#### Byzantine Leader Signatures — `ByzantineLeaderSignatureTest` (3 tests)

Tests for detecting and handling forged or invalid signatures from Byzantine leaders:

| Test | Threat addressed |
|------|-----------------|
| `byzantineLeaderModifiesCommandValueSignatureMismatch` | Leader modifies command value but keeps original signature; replica votes in PREPARE (signature validation deferred to execution) |
| `byzantineLeaderSwapsCommandAndSignature` | Leader uses signature from request A but command from request B; replica votes in PREPARE (signature validation deferred to execution) |
| `honestLeaderWithValidSignatureReplicaVotes` | Positive control: honest leader with valid signature; replica correctly votes in PREPARE |

#### Client Protocol — `DepChainClientTest` (7 tests)

Integration tests with mock nodes using real authenticated perfect links:

| Test | What it demonstrates |
|------|---------------------|
| `happyPath` | All 4 nodes respond with valid `CommitProof`; client accepts |
| `noCommitProofCausesTimeout` | No valid proofs; client times out |
| `singleValidResponseSuffices` | One valid `CommitProof` is enough (it proves quorum agreement) |
| `multipleSequentialRequests` | Client submits back-to-back requests on the same connection |
| `byzantineNodeForgedCommitProofIsRejected` | Forged proofs are discarded; valid one is accepted |
| `allNodesForgedCommitProofCausesTimeout` | All forged proofs; client times out |
| `multipleClientsConcurrentRequests` | Three clients append concurrently; all succeed |

#### Transaction Processing — `TransactionProcessingTest` (3 tests)

End-to-end transaction processing through the consensus pipeline:

| Test | What it demonstrates |
|------|---------------------|
| `testThreeClientsValidTransactions` | Three transactions processed correctly by all 4 nodes |
| `testInvalidSignatureRejected` | Transactions with invalid signatures are rejected |
| `testRequestOrderingPerClientNotByFee` | Per-client request ordering is enforced |

#### Duplicate Request Prevention — `DuplicateRequestIdPreventionTest` (3 tests)

Tests ensuring duplicate or replayed requests are correctly rejected:

| Test | What it demonstrates |
|------|---------------------|
| `duplicatePrepareInSameViewIsRejected` | Duplicate PREPARE in the same view is rejected |
| `duplicatePrepareInDifferentViewIsRejected` | Duplicate PREPARE across views is rejected |
| `duplicatePrepareWithDifferentValueInSameViewIsRejected` | Conflicting value with same ID in same view is rejected |

#### Service State — `UpcallHandlerTest` (6 tests)

Unit tests for the state handling and transaction execution layer:

| Test | What it demonstrates |
|------|---------------------|
| `appendSendsOkResponse` | A decided transaction is executed and response sent back |
| `duplicateRequestIdIgnored` | Duplicate request IDs are silently dropped (idempotency) |
| `distinctRequestIdsEachExecuted` | Distinct requests are both executed independently |
| `invalidGasParamsReturnFailure` | Zero gas limit or gas price returns a failure response |
| `testModeConstructorNoResponse` | Minimalist constructor (no network) does not crash on execution |
| `insufficientBalanceFails` | Transaction with insufficient balance to cover gas cost fails |

#### Request Order Enforcement — `RequestOrderEnforcementTest` (2 tests)

Tests for sequential request ID enforcement per client:

| Test | What it demonstrates |
|------|---------------------|
| `outOfOrderRequestIsRejected` | Request with ID=2 before ID=1 is rejected by the node |
| `multipleClientsHaveIndependentSequences` | Each client maintains an independent request ID sequence |

#### Duplicate Client Request — `BlockchainMemberTest` (1 test)

Tests that a duplicate `CLIENT_REQUEST` delivered to `BlockchainMember.ParseMessage` is proposed only once (deduplication at the gateway layer).

| Test | What it demonstrates |
|------|---------------------|
| `duplicateClientRequestIsProposedOnlyOnceInParseMessageFlow` | Duplicate `CLIENT_REQUEST` is proposed only once via `ParseMessage` (gateway deduplication) |

#### Client Utilities — `RequestTranslatorTest` (5 tests), `ResponseCollectorTest` (5 tests)

Unit tests for client-side request construction and response collection logic:

**RequestTranslatorTest:**

| Test | What it demonstrates |
|------|---------------------|
| `createTransactionPopulatesFields` | All ClientRequest fields are correctly populated |
| `createTransactionContentIsValidJson` | Serialized message content is valid JSON that round-trips correctly |
| `parseResponseRoundTrip` | ClientResponse is correctly deserialized from JSON |
| `differentValuesProduceDifferentMessages` | Different parameters produce distinct serialized messages |
| `parseResponseHandlesFailure` | Failed response preserves error message through serialization |

**ResponseCollectorTest:**

| Test | What it demonstrates |
|------|---------------------|
| `noResponseCausesTimeout` | Collector times out when no response arrives |
| `firstCompleteReleasesImmediately` | First `complete()` call releases the waiting latch immediately |
| `secondCompleteIsIgnored` | Second `complete()` is dropped; first result is preserved |
| `timeoutWhenNeverCompleted` | Collector times out when `complete()` is never called |
| `concurrentCompletionsAreSafe` | Thread-safe under concurrent `complete()` calls; first wins |

#### Cryptography — `PKIProviderThreshTest` (5 tests)

Integration tests for the cryptographic primitives:

| Test | What it demonstrates |
|------|---------------------|
| `testThresholdSignAndVerify` | k-of-l threshold signatures are correctly generated and verified |
| `testDifferentSubset` | A different subset of k shares also verifies correctly |
| `testCorruptDataFails` | Tampered message data fails threshold signature verification |
| `testGroupKeyConsistencyAcrossNodes` | All nodes derive the same shared group key |
| `testEcdsaSignAndVerify` | ECDSA cross-verification between different key pairs works correctly |

#### Networking — `TestBidirectionalTest`, `TestNodeDownTest` (2 tests)

Tests for the authenticated perfect links layer:

| Test | What it demonstrates |
|------|---------------------|
| `testBidirectional` | Two nodes exchange messages reliably in both directions |
| `testNodeDown` | APL handles node crashes (retransmission) and automatic reconnection |

#### Threshold Signatures — `ThreshTest` (4 tests)

Integration tests for the threshold signature library (Shoup's scheme):

| Test | What it demonstrates |
|------|---------------------|
| `testVerifySignatures` | Valid set of k threshold key shares produces a verifiable group signature |
| `testVerifySignaturesAgain` | A different subset of k shares also produces a valid group signature |
| `testVerifyBadSignature` | Corrupted signature share causes verification to fail |
| `testPerformance` | Signing and verification performance benchmarks complete within bounds |

## Manual Testing

A comprehensive manual testing guide is available in [`MANUAL_TESTING_GUIDE.md`](MANUAL_TESTING_GUIDE.md). It covers 6 end-to-end scenarios:

1. **Network Boot & Genesis Verification** — Nodes load genesis state and deploy the ISTCoin contract
2. **Native DepCoin & Gas Deductions** — Native transfers with gas fee verification
3. **ERC-20 Frontrunning Mitigation** — Demonstrates that the Approval Frontrunning attack is blocked
4. **Mempool Dynamics (Block Gas Limit)** — Block gas limit enforcement and transaction deferral
5. **Fee Market & Greedy Algorithm** — Transaction ordering by profitability
6. **BFT Catch-Up / Synchronization** — Block recovery after temporary node disconnection
