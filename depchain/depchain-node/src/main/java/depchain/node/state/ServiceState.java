package depchain.node.state;

import com.google.gson.Gson;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.fluent.SimpleWorld;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashSet;
import java.util.Set;

public class ServiceState {
    private final List<String> state; // Legacy state array
    private final SimpleWorld world;  // EVM world state
    private final Set<Address> trackedAccounts; // Track all accounts

    // Path to genesis.json for initializing the world state
    private static final String GENESIS_PATH = "../config/genesis.json";

    // DTOs for parsing genesis.json
    private static class GenesisBlock {
        List<GenesisTx> transactions;
        Map<String, AccountInfo> state;
    }

    private static class AccountInfo {
        String balance;
        int nonce;
    }

    private static class GenesisTx {
        String from;
        String to;
        long value;
        long gasLimit;
        long gasPrice;
        String data;
        Long requestId; 
        Long timestamp;
        String signature;
    }

    public ServiceState() {
        this.state = new ArrayList<>();
        this.world = new SimpleWorld();
        this.trackedAccounts = new LinkedHashSet<>();
        loadGenesisBlock();
    }

    /** Parses genesis.json and initializes the EVM world state. */
    private void loadGenesisBlock() {
        try {
            if (!Files.exists(Paths.get(GENESIS_PATH))) {
                System.err.println("Genesis file not found at " + GENESIS_PATH);
                return;
            }

            Gson gson = new Gson();
            GenesisBlock genesis = gson.fromJson(new FileReader(GENESIS_PATH), GenesisBlock.class);

            // Initialize accounts and balances
            if (genesis.state != null) {
                for (Map.Entry<String, AccountInfo> entry : genesis.state.entrySet()) {
                    Address addr = Address.fromHexString(entry.getKey());
                    Wei balance = Wei.of(Long.parseLong(entry.getValue().balance));
                    world.createAccount(addr, entry.getValue().nonce, balance);
                    trackAccount(addr);
                    System.out.println("Genesis: Funded account " + addr + " with " + balance.toLong() + " DepCoin");
                }
            }

            // Deploy initial smart contracts via EVM execution
            if (genesis.transactions != null) {
                var updater = world.updater();
                org.hyperledger.besu.evm.EVM evm = org.hyperledger.besu.evm.MainnetEVMs.cancun(org.hyperledger.besu.evm.internal.EvmConfiguration.DEFAULT);
                
                org.hyperledger.besu.evm.frame.BlockValues blockValues = new org.hyperledger.besu.evm.frame.BlockValues() {
                    @Override public org.apache.tuweni.bytes.Bytes getDifficultyBytes() { return org.apache.tuweni.bytes.Bytes32.ZERO; }
                    @Override public long getNumber() { return 0; }
                    @Override public long getTimestamp() { return 0; }
                    @Override public long getGasLimit() { return 30_000_000L; }
                };

                for (GenesisTx tx : genesis.transactions) {
                    // Check for contract creation
                    if (tx.to == null || tx.to.isEmpty()) {
                        
                        Address deployer = Address.fromHexString(tx.from);
                        
                        // Calculate deterministic address
                        Address contractAddr = Address.contractAddress(deployer, 0L);

                        // Track deployer and generated contract
                        trackAccount(deployer);
                        trackAccount(contractAddr);

                        // Ensure accounts exist
                        updater.getOrCreate(deployer);
                        updater.getOrCreate(contractAddr);
                        
                        // Prepare bytecode
                        Bytes fullInputData = Bytes.fromHexString(tx.data);
                        org.hyperledger.besu.evm.Code deploymentCode = evm.getCode(
                                org.hyperledger.besu.datatypes.Hash.hash(fullInputData), 
                                fullInputData
                        );

                        // Build EVM frame
                        org.hyperledger.besu.evm.frame.MessageFrame frame = org.hyperledger.besu.evm.frame.MessageFrame.builder()
                                .type(org.hyperledger.besu.evm.frame.MessageFrame.Type.CONTRACT_CREATION)
                                .worldUpdater(updater)
                                .initialGas(30_000_000L)
                                .address(contractAddr)
                                .contract(contractAddr)
                                .originator(deployer)
                                .sender(deployer)
                                .gasPrice(Wei.ZERO)
                                .inputData(Bytes.EMPTY)
                                .value(Wei.ZERO)
                                .apparentValue(Wei.ZERO)
                                .code(deploymentCode)
                                .blockValues(blockValues)
                                .miningBeneficiary(Address.ZERO)
                                .blockHashLookup((f, b) -> org.hyperledger.besu.datatypes.Hash.EMPTY)
                                .completer(c -> {})
                                .build();

                        // Run EVM execution
                        frame.setState(org.hyperledger.besu.evm.frame.MessageFrame.State.CODE_EXECUTING);
                        evm.runToHalt(frame, null);

                        // Verify execution state
                        var finalState = frame.getState();
                        boolean isSuccess = finalState == org.hyperledger.besu.evm.frame.MessageFrame.State.COMPLETED_SUCCESS || 
                                          finalState == org.hyperledger.besu.evm.frame.MessageFrame.State.CODE_SUCCESS;

                        if (isSuccess) {
                            var deployedAcc = updater.getOrCreate(contractAddr);
                            // Store runtime bytecode
                            deployedAcc.setCode(frame.getOutputData());
                            System.out.println("Genesis: ISTCoin deployed deterministically at " + contractAddr.toHexString());
                        } else {
                            System.err.println("Genesis Deploy Failed: " + finalState);
                        }
                    }
                }
                updater.commit();
            }
            
        } catch (Exception e) {
            System.err.println("Failed to load Genesis block: " + e.getMessage());
        }
    }

    /** Returns the active EVM world state. */
    public SimpleWorld getWorld() {
        return world;
    }

    /** Appends a decided command to the array. */
    public void append(String command) {
        state.add(command);
    }

    /** Returns a snapshot of all decided commands. */
    public List<String> getState() {
        return new ArrayList<>(state);
    }

    /** Safely track an account. */
    public void trackAccount(Address address) {
        if (address != null) {
            trackedAccounts.add(address);
        }
    }

    /** Get all tracked accounts. */
    public List<Address> getAllAccounts() {
        return new ArrayList<>(trackedAccounts);
    }

    /** Check if an account is tracked (i.e., exists in the system). */
    public boolean isAccountTracked(Address address) {
        return address != null && trackedAccounts.contains(address);
    }
}