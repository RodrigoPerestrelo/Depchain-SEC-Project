package depchain.node.state;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;
import depchain.common.protocol.CommitProof;
import depchain.common.utils.StaticMembership;
import depchain.node.consensus.QuorumCertificate;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.EvmSpecVersion;
import org.hyperledger.besu.evm.fluent.EVMExecutor;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.EVM;
import org.hyperledger.besu.evm.MainnetEVMs;
import org.hyperledger.besu.evm.tracing.StandardJsonTracer;
import org.hyperledger.besu.evm.processor.MessageCallProcessor;
import org.hyperledger.besu.evm.processor.ContractCreationProcessor;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.evm.frame.BlockValues;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import java.security.MessageDigest;

public class UpcallHandler {
    private final ServiceState serviceState;
    private final Network network;
    private final StaticMembership membership;
    private final int myNodeId;
    private final PKIProvider pki;

    // Block sequence number
    private int blockHeight = 1;

    // Deduplication: track already-executed client request IDs
    private final Set<String> executedRequestIds = new HashSet<>();

    // Track previous block hash for the chain
    private String previousBlockHash = "0x0000000000000000000000000000000000000000000000000000000000000000";

    // Per-node block storage directory
    private static final String BLOCK_NODE_PATH = "../config/blocks/node_";

    /**
     * Verifies if a client request has already been executed.
     * Used by BlockchainMember to prevent duplicate PREPAREs from being processed.
     */
    public boolean isRequestAlreadyExecuted(int clientId, int requestId) {
        String uniqueReqId = String.valueOf(clientId) + '-' + requestId;
        return executedRequestIds.contains(uniqueReqId);
    }

    /** Full constructor for production use. */
    public UpcallHandler(ServiceState serviceState, Network network,
                         StaticMembership membership, int myNodeId, PKIProvider pki) {
        this.serviceState = serviceState;
        this.network      = network;
        this.membership   = membership;
        this.myNodeId     = myNodeId;
        this.pki          = pki;
    }

    /** Backward-compatible constructor for tests (no signing/verification). */
    public UpcallHandler(ServiceState serviceState) {
        this(serviceState, null, null, -1, null);
    }

    /**
     * Backward-compatible single-argument overload used by tests and
     * legacy call sites that have no commitQC available.
     */
    public void execute(ClientRequest request) {
        execute(request, null, true);
    }

    /**
     * Executes a committed command and sends a CLIENT_RESPONSE to the
     * originating client. The response carries the commitQC wrapped as
     * a CommitProof — the client verifies the threshold signature instead
     * of collecting 2f+1 per-node ECDSA signatures.
     *
     * @param command   the JSON-encoded ClientRequest
     * @param commitQC  the consensus commit certificate (may be null in
     *                  test / backward-compat mode; response is sent unsigned)
     */
    public void execute(ClientRequest req, QuorumCertificate commitQC, boolean sendReply) {

        if (req != null) {
            // Defense-in-depth: verify request signature even if leader already checked it.
            // This ensures a Byzantine leader cannot commit unsigned commands.
            if (pki != null && !verifyRequestSignature(req)) {
                System.err.println(">>> REJECTED command with invalid/missing client signature: "
                        + req.getRequestId());
                return;
            }

            // Deduplication check
            String uniqueReqId = String.valueOf(req.getClientId()) + '-' + req.getRequestId();
            if (executedRequestIds.contains(uniqueReqId)) {
                return;
            }
            executedRequestIds.add(uniqueReqId);

            boolean success = false;
            String resultMessage = "ERROR";

            try {
                // Extract EVM parameters
                String to = req.getTo();
                long value = req.getValue();
                long gasLimit = req.getGasLimit();
                long gasPrice = req.getGasPrice();
                String data = req.getData();

                if (gasLimit <= 0 || gasPrice <= 0) {
                    throw new RuntimeException("Gas limit and gas price must be > 0");
                }

                // Map IDs to address space
                Address sender = Address.fromHexString(String.format("0x00000000000000000000000000000000000000c%x", req.getClientId()));
                Address receiver = (to != null && !to.isEmpty()) ? Address.fromHexString(to) : null;
                int minerId = (commitQC != null) ? membership.getLeader(commitQC.getViewNumber()) : myNodeId;
                Address minerAddress = Address.fromHexString(String.format("0x00000000000000000000000000000000000000a%x", minerId));

                // 1. Top-level updater (Fees and Nonces - Persistence level)
                var topUpdater = serviceState.getWorld().updater();
                var senderAcc = topUpdater.getOrCreate(sender);

                // Upfront Check: Validate liquidity before consuming nonce
                long maxGasFee = gasLimit * gasPrice;
                Wei totalUpfrontCost = Wei.of(maxGasFee).add(Wei.of(value));
                if (senderAcc.getBalance().compareTo(totalUpfrontCost) < 0) {
                    throw new RuntimeException("Insufficient balance to cover gas limit + value");
                }

                // Increment Nonce for non-repudiation (Always happens for valid txs)
                senderAcc.setNonce(senderAcc.getNonce() + 1);

                // 2. Child updater (EVM Isolation - Sandbox level)
                var evmUpdater = topUpdater.updater();
                long actualGasUsed;

                // Native balance flag
                boolean isNativeBalanceCheck = "NATIVE_BALANCE".equals(data);
                boolean isSimpleTransfer = (receiver != null) && (data == null || data.isEmpty());

                if (isNativeBalanceCheck) {
                    long intrinsicGas = 21000;
                    if (gasLimit < intrinsicGas) {
                        actualGasUsed = gasLimit;
                        resultMessage = "EXECUTION REVERTED: OUT_OF_GAS (Intrinsic)";
                    } else {
                        actualGasUsed = intrinsicGas;

                        // Determine the account to query
                        Address queryAddr = (receiver != null) ? receiver : sender;

                        // Validate that the queried account exists in the system
                        if (!serviceState.isAccountTracked(queryAddr)) {
                            resultMessage = "EXECUTION REVERTED: Account does not exist: " + queryAddr.toHexString();
                        } else {
                            // Fetch target account balance
                            var targetAcc = topUpdater.getAccount(queryAddr);
                            long bal = (targetAcc != null) ? targetAcc.getBalance().toLong() : 0L;

                            // Append balance to result
                            resultMessage = "EVM_TX_SUCCESS (Gas Used: 21000) | Native Balance: " + bal;
                            success = true;
                        }
                    }
                 } else if (isSimpleTransfer) {
                    long intrinsicGas = 21000;
                    if (gasLimit < intrinsicGas) {
                        actualGasUsed = gasLimit;
                        resultMessage = "EXECUTION REVERTED: OUT_OF_GAS (Intrinsic)";
                    } else {
                        actualGasUsed = intrinsicGas;
                        if (value > 0) {
                            var evmReceiverAcc = evmUpdater.getOrCreate(receiver);
                            var evmSenderAcc = evmUpdater.getOrCreate(sender);
                            evmSenderAcc.setBalance(evmSenderAcc.getBalance().subtract(Wei.of(value)));
                            evmReceiverAcc.setBalance(evmReceiverAcc.getBalance().add(Wei.of(value)));
                        }
                        evmUpdater.commit(); // Merge transfer into topUpdater
                        resultMessage = "EVM_TX_SUCCESS (Gas Used: 21000)";
                        success = true;
                    }
                } else {
                    // Smart Contract execution logic
                    EVM evm = MainnetEVMs.cancun(EvmConfiguration.DEFAULT);
                    Address targetAddress = (receiver != null) ? receiver : Address.contractAddress(sender, senderAcc.getNonce() - 1);
                    Bytes inputBytes = (data != null && !data.isEmpty()) ? Bytes.fromHexString(data) : Bytes.EMPTY;
                    Code targetCode;
                    
                    if (receiver == null) {
                        targetCode = evm.getCode(Hash.hash(inputBytes), inputBytes);
                    } else {
                        var receiverAcc = evmUpdater.get(receiver);
                        if (receiverAcc != null && receiverAcc.getCode() != null) {
                            targetCode = evm.getCode(Hash.hash(receiverAcc.getCode()), receiverAcc.getCode());
                        } else {
                            targetCode = evm.getCode(Hash.EMPTY, Bytes.EMPTY);
                        }
                    }

                    BlockValues blockValues = new BlockValues() {
                        @Override public Bytes getDifficultyBytes() { return org.apache.tuweni.bytes.Bytes32.ZERO; }
                        @Override public long getNumber() { return blockHeight; }
                        @Override public long getTimestamp() { return System.currentTimeMillis() / 1000; }
                        @Override public long getGasLimit() { return 30_000_000L; }
                    };

                    MessageFrame frame = MessageFrame.builder()
                            .type(receiver == null ? MessageFrame.Type.CONTRACT_CREATION : MessageFrame.Type.MESSAGE_CALL)
                            .worldUpdater(evmUpdater) // Use isolated updater
                            .initialGas(gasLimit - 21000)
                            .address(targetAddress)
                            .contract(targetAddress)
                            .originator(sender)
                            .sender(sender)
                            .gasPrice(Wei.of(gasPrice))
                            .inputData(receiver != null ? inputBytes : Bytes.EMPTY)
                            .value(Wei.of(value))
                            .apparentValue(Wei.of(value))
                            .code(targetCode)
                            .blockValues(blockValues)
                            .miningBeneficiary(minerAddress)
                            .blockHashLookup((f, b) -> Hash.EMPTY)
                            .completer(c -> {})
                            .build();

                    frame.setState(MessageFrame.State.CODE_EXECUTING);
                    evm.runToHalt(frame, null);

                    actualGasUsed = gasLimit - frame.getRemainingGas();
                    success = (frame.getState() == MessageFrame.State.COMPLETED_SUCCESS || 
                               frame.getState() == MessageFrame.State.CODE_SUCCESS);
                    
                    if (success) {
                        // Success: Save bytecode and commit EVM changes to topUpdater
                        if (receiver == null) {
                            var deployedAcc = evmUpdater.getOrCreate(targetAddress);
                            deployedAcc.setCode(frame.getOutputData());
                        }
                        evmUpdater.commit(); 
                        
                        resultMessage = "EVM_TX_SUCCESS (Gas Used: " + actualGasUsed + ")";
                        Bytes output = frame.getOutputData();
                        if (output != null && !output.isEmpty()) {
                            resultMessage += " | ReturnData: " + output.toHexString();
                        }
                    } else {
                        // Failure/Revert: Charge gas limit, discard evmUpdater changes
                        actualGasUsed = gasLimit;
                        resultMessage = "EXECUTION REVERTED: " + frame.getState().name();
                    }
                }

                // 3. Finalize Fees (Deduct from topUpdater)
                long actualGasFee = actualGasUsed * gasPrice;
                senderAcc.setBalance(senderAcc.getBalance().subtract(Wei.of(actualGasFee)));

                // 4. Reward Miner
                var minerAcc = topUpdater.getOrCreate(minerAddress);
                minerAcc.setBalance(minerAcc.getBalance().add(Wei.of(actualGasFee)));

                // 5. Final Commit to persistent world state
                topUpdater.commit();

                if (!success) {
                    System.err.println(">>> EVM HALTED: " + resultMessage);
                }

            } catch (Exception e) {
                // Case 3: Rejection (No commit, Nonce/Balance unchanged)
                resultMessage = "EXECUTION FAILED: " + e.getMessage();
                System.err.println(">>> STATE UPDATE REJECTED: " + e.getMessage());
            }

            // Send CLIENT_RESPONSE carrying the commitQC as a CommitProof.
            // The CommitProof (threshold signature over the decided block) allows
            // the client to verify consensus with a single message verification.
            if (network != null && membership != null && sendReply) {
                try {
                    ClientResponse resp = new ClientResponse(
                            req.getRequestId(), success, resultMessage, myNodeId);

                    if (commitQC != null) {
                        CommitProof proof = new CommitProof(
                                commitQC.getType(),
                                commitQC.getViewNumber(),
                                commitQC.getNode().computeHash(),
                                commitQC.getSigs());
                        resp.setCommitProof(proof);
                    }

                    StaticMembership.NodeInfo clientInfo = membership.getClient(req.getClientId());
                    if (clientInfo != null) {
                        network.send(clientInfo.getAddress(), clientInfo.getPort(),
                                new Message(resp.toJson(), "CLIENT_RESPONSE"));
                    }
                } catch (Exception e) {
                    System.err.println("Failed to send CLIENT_RESPONSE: " + e.getMessage());
                }
            }
        } else { // Internal command (e.g. genesis-tx) — not appended to state
            System.out.println(">>> INTERNAL COMMAND (not appended to state)");
        }
    }

    /**
     * Verifies the ECDSA signature on a client request.
     * The signature covers ClientRequest#getCanonicalBytes(), signed with
     * the client's static ECDSA private key (identified by req.getClientId()).
     */
    private boolean verifyRequestSignature(ClientRequest req) {
        if (req.getSignature() == null) return false;
        try {
            byte[] sig = Base64.getDecoder().decode(req.getSignature());
            return pki.verify(req.getSigningData(), sig, req.getClientId());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Persist block to disk.
     */
    public void persistBlock(depchain.node.consensus.Block block) {
        try {
            // Isolate block storage per node
            File dir = new File(BLOCK_NODE_PATH + myNodeId);
            if (!dir.exists()) dir.mkdirs();

            var updater = serviceState.getWorld().updater();
            
            // Get accounts
            List<Address> accounts = serviceState.getAllAccounts();

            // Build state JSON
            StringBuilder stateBuilder = new StringBuilder("{\n");
            for (int i = 0; i < accounts.size(); i++) {
                Address addr = accounts.get(i);
                var acc = updater.getAccount(addr);
                long balance = acc != null ? acc.getBalance().toLong() : 0;
                long nonce = acc != null ? acc.getNonce() : 0;
                
                stateBuilder.append(String.format("    \"%s\": {\n", addr.toHexString()));
                stateBuilder.append(String.format("      \"balance\": \"%d\",\n", balance));
                stateBuilder.append(String.format("      \"nonce\": %d\n    }", nonce));
                if (i < accounts.size() - 1) stateBuilder.append(",\n");
                else stateBuilder.append("\n  }");
            }

            // Build tx array JSON
            StringBuilder txBuilder = new StringBuilder();
            List<ClientRequest> txs = block.getTransactions();
            
            if (txs != null) {
                for (int i = 0; i < txs.size(); i++) {
                    ClientRequest req = txs.get(i);
                    
                    // Convert clientId to hex address
                    String fromAddress = String.format("0x%040x", 0xc0 + req.getClientId());
                    String toAddress = (req.getTo() != null && !req.getTo().isEmpty()) ? "\"" + req.getTo() + "\"" : "null";
                    String dataStr = req.getData() != null ? req.getData() : "";
                    
                    // Format JSON string
                    String txJson = "{" +
                            "\"from\":\"" + fromAddress + "\"," +
                            "\"to\":" + toAddress + "," +
                            "\"value\":" + req.getValue() + "," +
                            "\"gasLimit\":" + req.getGasLimit() + "," +
                            "\"gasPrice\":" + req.getGasPrice() + "," +
                            "\"data\":\"" + dataStr + "\"," +
                            "\"requestId\":" + req.getRequestId() + "," +
                            "\"timestamp\":" + req.getTimestamp() + "," +
                            "\"signature\":\"" + req.getSignature() + "\"" +
                            "}";
                            
                    txBuilder.append("    ").append(txJson);
                    if (i < txs.size() - 1) txBuilder.append(",\n");
                }
            }

            String blockContent = "{\n" +
                    "  \"previous_block_hash\": \"" + previousBlockHash + "\",\n" +
                    "  \"transactions\": [\n" + txBuilder.toString() + "\n  ],\n" +
                    "  \"state\": " + stateBuilder.toString() + "\n}";

            // Calculate hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(blockContent.getBytes(StandardCharsets.UTF_8));
            StringBuilder hashHex = new StringBuilder("0x");
            for (byte b : hashBytes) hashHex.append(String.format("%02x", b));
            String blockHash = hashHex.toString();

            String finalJson = "{\n  \"block_hash\": \"" + blockHash + "\",\n" + blockContent.substring(2);

            // Write to file
            String fileName = "block_" + (blockHeight++) + ".json";
            Files.writeString(Paths.get(dir.getAbsolutePath(), fileName), finalJson);

            previousBlockHash = blockHash;

        } catch (Exception e) {
            System.err.println("Failed to persist block: " + e.getMessage());
        }
    }
}