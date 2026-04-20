package depchain.client.core;

import depchain.client.protocol.ResponseValidator.ResponseCollector;
import depchain.common.crypto.PKIProvider;
import depchain.common.network.AuthenticatedPerfectLinks;
import depchain.common.network.Message;
import depchain.common.network.Packet;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;
import depchain.common.protocol.CommitProof;
import depchain.common.utils.StaticMembership;

import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class DepChainClient {

    private static final long DEFAULT_TIMEOUT_SECONDS = 60;

    private final int clientId;
    private final StaticMembership membership;
    private final AuthenticatedPerfectLinks apl;
    private final PKIProvider pki;
    private final AtomicInteger requestCounter = new AtomicInteger(0);

    // Maps requestId -> pending response collector
    private final ConcurrentHashMap<Integer, ResponseCollector> pendingRequests =
            new ConcurrentHashMap<>();

    // Client's own peerIds map (address -> nodeId) for verified sender lookup
    private final Map<InetSocketAddress, Integer> peerIds;

    public DepChainClient(int clientId, String nodesPath, String clientsPath, String keysPath) throws Exception {
        this.clientId   = clientId;
        this.membership = new StaticMembership(nodesPath, clientsPath);

        int totalEntities = membership.getTotalEntities();
        // Load with threshold keys so the client can verify CommitProofs (GroupKey only).
        // The client has no per-node KeyShare; the constructor handles that gracefully.
        this.pki = new PKIProvider(keysPath, clientId, totalEntities, true);

        StaticMembership.NodeInfo myInfo = membership.getClient(clientId);
        if (myInfo == null) {
            throw new IllegalArgumentException("Client ID " + clientId + " not found in config");
        }
        int clientPort = myInfo.getPort();

        // Build peerIds map with all nodes
        this.peerIds = new HashMap<>();
        for (StaticMembership.NodeInfo node : membership.getAllNodes()) {
            InetSocketAddress addr = new InetSocketAddress(node.getAddress(), node.getPort());
            peerIds.put(addr, node.getId());
        }

        this.apl = new AuthenticatedPerfectLinks(clientPort, clientId, pki, peerIds);

        startResponseListener();
    }

    /**
     * Submits an EVM transaction and blocks until a node responds with a valid CommitProof.
     */
    public String sendTransaction(String to, long value, long gasLimit, long gasPrice, String data) throws Exception {
        return sendTransaction(to, value, gasLimit, gasPrice, data, DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public String sendTransaction(String to, long value, long gasLimit, long gasPrice, String data, long timeout, TimeUnit unit) throws Exception {
        int requestId = requestCounter.incrementAndGet();
        long timestamp = System.currentTimeMillis();

        // Build and sign the request with the client's ECDSA private key
        ClientRequest req = new ClientRequest(clientId, requestId, to, value, gasLimit, gasPrice, data, timestamp);
        byte[] sig = pki.sign(req.getSigningData());
        req.setSignature(Base64.getEncoder().encodeToString(sig));
        
        Message msg = new Message(req.toJson(), "CLIENT_REQUEST");

        ResponseCollector collector = new ResponseCollector();
        pendingRequests.put(requestId, collector);

        // Broadcast to ALL nodes
        for (StaticMembership.NodeInfo node : membership.getAllNodes()) {
            apl.send(node.getAddress(), node.getPort(), msg);
        }

        try {
            return collector.await(timeout, unit);
        } finally {
            pendingRequests.remove(requestId);
        }
    }

    /**
     * Background thread that receives all messages from nodes and routes
     * them to the appropriate pending request collector.
     */
    private void startResponseListener() {
        Thread listener = new Thread(() -> {
            while (true) {
                try {
                    Packet packet = apl.deliverPacket();
                    Message msg = packet.getMessage();
                    String type = msg.getType();

                    if (!"CLIENT_RESPONSE".equals(type)) {
                        continue;
                    }

                    // Resolve verified sender from UDP source address (transport-authenticated)
                    InetSocketAddress senderAddr = new InetSocketAddress(
                            packet.getAddress(), packet.getPort());
                    Integer verifiedNodeId = peerIds.get(senderAddr);
                    if (verifiedNodeId == null) {
                        System.err.println("[Client] Response from unknown address: " + senderAddr);
                        continue;
                    }

                    ClientResponse resp = ClientResponse.fromJson(msg.getContent());

                    // Verify the CommitProof (threshold signature = consensus proof).
                    // A single valid CommitProof is sufficient: it was formed from
                    // 2f+1 COMMIT votes and cannot be forged without k signing keys.
                    CommitProof proof = resp.getCommitProof();
                    if (proof == null) {
                        System.err.println("[Client] Dropped response from node " + verifiedNodeId
                                + ": missing CommitProof");
                        continue;
                    }
                    try {
                        if (!pki.verifyCommitProof(proof)) {
                            System.err.println("[Client] Dropped response from node " + verifiedNodeId
                                    + ": invalid CommitProof");
                            continue;
                        }
                    } catch (Exception e) {
                        System.err.println("[Client] Dropped response from node " + verifiedNodeId
                                + ": CommitProof verification error: " + e.getMessage());
                        continue;
                    }

                    System.out.println("[Client] Response from node " + verifiedNodeId
                            + " (CommitProof verified): " + resp.getResult());

                    ResponseCollector collector = pendingRequests.get(resp.getRequestId());
                    if (collector != null) {
                        collector.complete(resp.getResult());
                    }

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    System.err.println("[Client] Error in response listener: " + e.getMessage());
                }
            }
        }, "client-response-listener");
        listener.setDaemon(true);
        listener.start();
    }

    public void close() {
        apl.close();
    }
}
