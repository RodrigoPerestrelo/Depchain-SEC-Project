package depchain.node.core;

import depchain.common.utils.StaticMembership;
import depchain.common.crypto.PKIProvider;
import depchain.common.network.AuthenticatedPerfectLinks;
import depchain.common.network.Message;
import depchain.common.protocol.ClientRequest;
import depchain.node.consensus.HotStuffMessage;
import depchain.node.consensus.BasicHotStuff;
import depchain.node.consensus.Block;
import depchain.node.consensus.BlockFetchRequest;
import depchain.node.consensus.BlockFetchResponse;
import depchain.node.crypto.ThresholdSignatureService;
import depchain.node.state.ServiceState;
import depchain.node.state.UpcallHandler;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public class BlockchainMember {

    // Application-layer anti-duplicate guard by client/requestId.
    // APL guarantees ordered packet delivery per sender, but Byzantine behavior
    // can still replay same logical requestId at higher protocol layers.
    private static final Map<Integer, Integer> nextExpectedClientRequestId = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: java BlockchainMember <nodeId> <nodesPath> <clientsPath> <KeysDir>");
            System.exit(1);
        }

        try {
            int myId = Integer.parseInt(args[0]);
            String nodeConfigPath = args[1];
            String clientConfigPath = args[2];
            String keysPath = args[3];

            // Load Membership
            StaticMembership membership = new StaticMembership(nodeConfigPath, clientConfigPath);

            // Build peerIds map — nodes AND clients
            Map<Integer, InetSocketAddress> allNodes = new HashMap<>();
            Map<InetSocketAddress, Integer> peerIds = new HashMap<>();

            for (StaticMembership.NodeInfo node : membership.getAllNodes()) {
                InetSocketAddress addr = new InetSocketAddress(node.getAddress(), node.getPort());
                allNodes.put(node.getId(), addr);
                peerIds.put(addr, node.getId());
            }
            for (StaticMembership.NodeInfo client : membership.getAllClients()) {
                InetSocketAddress addr = new InetSocketAddress(client.getAddress(), client.getPort());
                peerIds.put(addr, client.getId());
            }

            // Load Crypto & State
            int totalEntities = membership.getTotalEntities();
            PKIProvider pki = new PKIProvider(keysPath, myId, totalEntities);
            ThresholdSignatureService tss = new ThresholdSignatureService(pki, myId);
            ServiceState state = new ServiceState();

            // Init Network
            int myPort = allNodes.get(myId).getPort();
            AuthenticatedPerfectLinks apl = new AuthenticatedPerfectLinks(myPort, myId, pki, peerIds);

            // Init UpcallHandler with PKI for signing/verifying
            UpcallHandler upcallHandler = new UpcallHandler(state, apl, membership, myId, pki);

            // Init Consensus — pass pki so the client-request registry check is enforced
            BasicHotStuff consensus = new BasicHotStuff(membership, myId, apl, tss, upcallHandler, pki);

            // Start the consensus event-loop thread
            consensus.start();

            while (true) {
                Message msg = apl.deliver();
                ParseMessage(msg, consensus, membership, myId, pki, upcallHandler);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void ParseMessage(Message msg, BasicHotStuff consensus,
                                     StaticMembership membership, int myId, PKIProvider pki,
                                     UpcallHandler upcallHandler) {
        String type = msg.getType();
        String content = msg.getContent();
        
        switch (type) {
            case "HOTSTUFF":
                HotStuffMessage hotMsg = HotStuffMessage.fromJson(content);

                // Verify client signatures in PREPARE blocks (prevents Byzantine leader command modification)
                if ("PREPARE".equals(hotMsg.getType()) && hotMsg.getNode() != null) {
                    if (!isValidClientSignatureInBlock(hotMsg.getNode(), pki)) {
                        System.err.println("[Node " + myId + "] Dropped PREPARE with invalid client signature in block");
                        break; // This break exits the switch, dropping the packet
                    }

                    // Prevent duplicate PREPAREs for the same clientId+requestId
                    // (defense against Byzantine leader replay attacks)
                    List<ClientRequest> transactions = hotMsg.getNode().getTransactions();
                    boolean hasDuplicate = false; // Add this flag

                    if (transactions != null) {
                        for (ClientRequest clientReq : transactions) {
                            if (clientReq == null) continue;
                            int clientId = clientReq.getClientId();
                            int requestId = clientReq.getRequestId();

                            // Stage 1: Check if this request has already been executed (production)
                            if (upcallHandler.isRequestAlreadyExecuted(clientId, requestId)) {
                                System.err.println(String.format(
                                    "[Node %d] Dropped PREPARE for already-executed request: clientId=%d requestId=%d",
                                    myId, clientId, requestId));
                                hasDuplicate = true; // Set flag
                                break; // Break the for loop
                            }
                        }   
                    }
                    
                    // Drop the packet entirely if ANY transaction was a duplicate
                    if (hasDuplicate) {
                        break;
                    }
                }
                consensus.addMessageToQueue(hotMsg);
                break;

            case "FETCH-BLOCKS-REQ":
                try {
                    BlockFetchRequest req = BlockFetchRequest.fromJson(content);
                    consensus.addBlockFetchRequest(req);
                } catch (Exception e) {
                    System.err.println("[Node " + myId + "] Failed to parse FETCH-BLOCKS-REQ: " + e.getMessage());
                }
                break;

            case "FETCH-BLOCKS-RESP":
                try {
                    BlockFetchResponse resp = BlockFetchResponse.fromJson(content);
                    
                    // Defend against forged blocks during recovery (array of blocks)
                    Block[] recoveredBlocks = resp.getBlocks();
                    boolean hasFakeBlock = false;
                    
                    if (recoveredBlocks != null) {
                        for (Block b : recoveredBlocks) {
                            if (b != null && !isValidClientSignatureInBlock(b, pki)) {
                                System.err.println("[Node " + myId + "] Dropped fake recovered block batch: invalid signatures");
                                hasFakeBlock = true;
                                break; 
                            }
                        }
                    }
                    
                    // Drop the entire response if any block in the array is forged
                    if (hasFakeBlock) {
                        break;
                    }
                    
                    consensus.addBlockFetchResponse(resp);
                } catch (Exception e) {
                    System.err.println("[Node " + myId + "] Failed to parse FETCH-BLOCKS-RESP: " + e.getMessage());
                }
                break;

            case "CLIENT_REQUEST":
                // Every node validates the client's ECDSA signature.
                // Message ordering is enforced by APL before delivery.
                ClientRequest req = null;
                try { req = ClientRequest.fromJson(content); } catch (Exception ignored) {}
                if (req == null || !isValidClientRequest(req, pki)) {
                    System.err.println("[Node " + myId + "] Dropped CLIENT_REQUEST with invalid signature");
                    break;
                }

                if (!isExpectedAndAdvance(nextExpectedClientRequestId, req.getClientId(), req.getRequestId())) {
                    int expected = nextExpectedClientRequestId.getOrDefault(req.getClientId(), 1);
                    System.err.println(String.format(
                            "[Node %d] Dropped CLIENT_REQUEST duplicate/out-of-order: clientId=%d requestId=%d expected=%d",
                            myId, req.getClientId(), req.getRequestId(), expected));
                    break;
                }

                // Forward to consensus for ordering (all nodes enqueue)
                consensus.proposeCommand(req);
                break;

            default:
                System.err.println("Unknown message type: " + type);
        }
    }
    /**
     * Returns true if the request carries a valid ECDSA signature from the
     * stated client.  A Byzantine node forging clientId cannot
     * produce a valid signature without that client's private key.
     */
    private static boolean isValidClientRequest(ClientRequest req, PKIProvider pki) {
        try {
            if (req.getSignature() == null) return false;
            byte[] sig = Base64.getDecoder().decode(req.getSignature());
            return pki.verify(req.getSigningData(), sig, req.getClientId());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns true if the block carries a valid client signature to prevent
     * Byzantine leaders from modifying commands after receiving them.
     */
    private static boolean isValidClientSignatureInBlock(Block block, PKIProvider pki) {
        if (pki == null) return true;  // backward compatibility mode

        for (ClientRequest tx : block.getTransactions()) {
            if (tx != null && !isValidClientRequest(tx, pki)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isExpectedAndAdvance(Map<Integer, Integer> nextExpectedMap,
                                                int clientId,
                                                int requestId) {
        if (requestId < 1) return false;

        final boolean[] accepted = { false };
        nextExpectedMap.compute(clientId, (k, currentExpected) -> {
            int expected = (currentExpected == null) ? 1 : currentExpected;
            if (requestId == expected) {
                accepted[0] = true;
                return expected + 1;
            }
            return expected;
        });

        return accepted[0];
    }

    public static void clearClientState() {
        nextExpectedClientRequestId.clear();
    }

}

