package depchain.common.network;

import depchain.common.crypto.PKIProvider;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Authenticated Perfect Links (APL) over UDP.
 *
 * Provides:
 *   APL1 - Reliable delivery (retransmit until ACKed)
 *   APL2 - No duplication (sliding-window deduplication)
 *   APL3 - Authenticity via per-session HMAC keys derived from ephemeral ECDH
 *
 * Before the first DATA message is sent to a peer, an ephemeral Diffie-Hellman
 * handshake is performed:
 *   1. Sender generates a fresh EC key pair and sends a HANDSHAKE packet containing
 *      the ephemeral public key, signed with its static ECDSA key (from PKIProvider).
 *   2. Receiver verifies the ECDSA signature, generates its own ephemeral key pair,
 *      and responds with its own HANDSHAKE.
 *   3. Both sides compute ECDH(myEphemeralPriv, peerEphemeralPub) and derive the
 *      HMAC key as Base64(SHA-256(sharedSecret)).
 *
 * Forward secrecy: a new ephemeral key pair is generated per session (per JVM run).
 * Authentication: the ECDSA signatures on the ephemeral keys prevent MITM attacks.
 */
public class AuthenticatedPerfectLinks implements Network {

    private static final String EC_ALGORITHM = "EC";
    private static final String EC_CURVE = "secp256r1";
    private static final long SESSION_TIMEOUT_MS = 15_000;
    private static final long GAP_WAIT_TIMEOUT_MS = 1_500;

    private final int myId;
    private final PKIProvider pki;
    // Maps peer InetSocketAddress -> their node ID (for ECDSA verification)
    private final Map<InetSocketAddress, Integer> peerIds;
    private final UDPLink udpLink;

    // --- Session state ---
    // Established sessions: peer -> derived HMAC key
    private final ConcurrentHashMap<InetSocketAddress, String> sessionKeys = new ConcurrentHashMap<>();
    // My ephemeral key pairs: peer -> KeyPair (generated on first contact)
    private final ConcurrentHashMap<InetSocketAddress, KeyPair> myEphemeralKeys = new ConcurrentHashMap<>();
    // Peer ephemeral public keys received in HANDSHAKE
    private final ConcurrentHashMap<InetSocketAddress, PublicKey> peerEphemeralKeys = new ConcurrentHashMap<>();
    // Tracks which peers we've already sent HANDSHAKE to (avoids duplicates)
    private final Set<InetSocketAddress> handshakeSent = ConcurrentHashMap.newKeySet();
    // Per-peer latches: released when the session is established
    private final ConcurrentHashMap<InetSocketAddress, CountDownLatch> sessionLatches = new ConcurrentHashMap<>();

    // --- Delivery queue ---
    private final BlockingQueue<Packet> eventQueue = new LinkedBlockingQueue<>();

    // Sequence-number generator per destination
    private final Map<InetSocketAddress, AtomicInteger> sequenceGenerators = new ConcurrentHashMap<>();

    // Thread pool optimised for I/O tasks that block on wait()
    private final ExecutorService sendExecutor = Executors.newCachedThreadPool();
    // Periodic checker to unblock delivery on sequence gaps after timeout.
    private final ScheduledExecutorService gapTimeoutExecutor = Executors.newSingleThreadScheduledExecutor();

    // --- Send state (APL1: Reliable Delivery) ---
    private static class AckMonitor {
        boolean isAcknowledged    = false;
        boolean maxRetriesExceeded = false;
    }
    // Outer key: destination (InetSocketAddress, computed once per send).
    // Inner key: sequence number (int). Zero string allocation on the hot path.
    private final Map<InetSocketAddress, ConcurrentHashMap<Integer, AckMonitor>> pendingAcks =
            new ConcurrentHashMap<>();

        // --- Receive state (APL2: No Duplication + in-order delivery) ---
        // Per sender: next sequence number expected for delivery.
        private final Map<InetSocketAddress, Integer> lowerBounds = new ConcurrentHashMap<>();
        // Per sender: out-of-order packets buffered until gaps are filled.
        private final Map<InetSocketAddress, ConcurrentHashMap<Integer, Packet>> pendingBySeq =
            new ConcurrentHashMap<>();
        // Per sender: when we first noticed a sequence gap (expected missing).
        private final Map<InetSocketAddress, Long> gapWaitStartMs = new ConcurrentHashMap<>();
        // Per sender: lock object to keep receive-state transitions atomic.
        private final ConcurrentHashMap<InetSocketAddress, Object> receiveLocks = new ConcurrentHashMap<>();

    /**
     * @param port      local UDP port to bind to
     * @param myId      this node's ID
     * @param pki       provides static ECDSA key pair for signing/verifying HANDSHAKE messages
     * @param peerIds   maps each peer's InetSocketAddress to their node ID
     * @throws Exception if the socket cannot be created
     */
    public AuthenticatedPerfectLinks(int port, int myId, PKIProvider pki,
                                     Map<InetSocketAddress, Integer> peerIds) throws Exception {
        this.myId = myId;
        this.pki = pki;
        this.peerIds = peerIds;
        this.udpLink = new UDPLink(port);

        startListenerThread();
        startGapTimeoutChecker();
    }

    // --- PUBLIC API ---

    /**
     * Sends content reliably to (destIp, destPort). Initiates ECDH handshake on first
     * contact and blocks until the session is established (or timeout).
     */
    public void send(InetAddress destIp, int destPort, Message msg) {
        sendExecutor.submit(() -> {
            try {
                InetSocketAddress dest = new InetSocketAddress(destIp, destPort);

                // Ensure session is established before sending DATA
                ensureSession(dest);

                String sessionKey = sessionKeys.get(dest);
                if (sessionKey == null) {
                    System.err.println("[APL] Session with " + dest + " not established after timeout, dropping message");
                    return;
                }

                int seqNum = sequenceGenerators
                        .computeIfAbsent(dest, k -> new AtomicInteger(0))
                        .incrementAndGet();

                Packet packet = new Packet(myId, "DATA", seqNum, msg, destIp, destPort);
                packet.sign(sessionKey); // APL3: Authenticity

                AckMonitor monitor = new AckMonitor();
                // Register before sending to avoid a race with a fast ACK
                pendingAcks.computeIfAbsent(dest, k -> new ConcurrentHashMap<>()).put(seqNum, monitor);

                try {
                    synchronized (monitor) {
                        int retries = 0;
                        while (!monitor.isAcknowledged) {
                            if (retries > 5) {
                                monitor.maxRetriesExceeded = true;
                                break;
                            }
                            // Re-sign on every attempt with the current session key.
                            // The session may have been renegotiated since the packet was
                            // first created; always using the latest key ensures the
                            // receiver can verify the HMAC after a re-handshake.
                            String currentKey = sessionKeys.get(dest);
                            if (currentKey == null) {
                                // Session re-establishment in progress; wait and retry.
                                monitor.wait(500);
                                retries++;
                                continue;
                            }
                            packet.sign(currentKey);
                            udpLink.send(packet);
                            monitor.wait(500); // only this background thread blocks
                            retries++;
                        }
                    }
                } finally {
                    // Always clean up, even if interrupted
                    ConcurrentHashMap<Integer, AckMonitor> destMap = pendingAcks.get(dest);
                    if (destMap != null) {
                        destMap.remove(seqNum);
                        // Clean up empty destination maps to prevent memory leaks
                        if (destMap.isEmpty()) {
                            pendingAcks.remove(dest, destMap); // atomic remove-if-same
                        }
                    }
                }

                if (monitor.isAcknowledged) {
                    System.out.println("[APL] ACK received for dest=" + dest + " seq=" + seqNum);
                } else if (monitor.maxRetriesExceeded) {
                    System.err.println("[APL] Max retries exceeded for dest=" + dest + " seq=" + seqNum + " — message dropped");
                }

            } catch (Exception e) {
                System.err.println("Error in send worker thread: " + e.getMessage());
            }
        });
    }

    /**
     * Blocks until the next authenticated, deduplicated message is available.
     *
     * @return the delivered message
     * @throws InterruptedException if the calling thread is interrupted while waiting
     */
    public Message deliver() throws InterruptedException {
        Packet p = eventQueue.take();
        return p.getMessage();
    }

    /**
     * Blocks until the next authenticated, deduplicated packet is available.
     * Unlike deliver(), this preserves the sender's UDP source address
     * for verified sender identification (BFT-critical).
     */
    public Packet deliverPacket() throws InterruptedException {
        return eventQueue.take();
    }

    /**
     * Shuts down this APL instance: closes the UDP socket and stops all send workers.
     * Any pending retries are abandoned immediately.
     */
    public void close() {
        udpLink.close();          // stops listener thread and causes pending sends to throw
        gapTimeoutExecutor.shutdownNow();
        sendExecutor.shutdownNow(); // interrupts send workers blocked on monitor.wait()
    }

    // --- HANDSHAKE ---

    /**
     * Ensures a session exists with the given peer. Sends a HANDSHAKE if not yet sent,
     * then waits up to SESSION_TIMEOUT_MS for completion.
     */
    private void ensureSession(InetSocketAddress peer) throws Exception {
        if (sessionKeys.containsKey(peer)) return;

        CountDownLatch latch = sessionLatches.computeIfAbsent(peer, k -> new CountDownLatch(1));

        // Check again after getting the latch (avoid race)
        if (sessionKeys.containsKey(peer)) return;

        initiateHandshakeIfNeeded(peer);

        boolean established = latch.await(SESSION_TIMEOUT_MS, TimeUnit.MILLISECONDS);

        // If the handshake timed out, reset state so the next send() can retry.
        // Without this, handshakeSent keeps the peer marked "already sent" forever
        // and initiateHandshakeIfNeeded becomes a permanent no-op.
        if (!established && !sessionKeys.containsKey(peer)) {
            sessionLatches.remove(peer, latch);
            handshakeSent.remove(peer);
        }
    }

    /** Sends a HANDSHAKE to the given peer if we haven't already. */
    private void initiateHandshakeIfNeeded(InetSocketAddress peer) {
        if (!handshakeSent.add(peer)) return; // already sent

        try {
            KeyPair ephemeral = myEphemeralKeys.get(peer);
            if (ephemeral == null) {
                ephemeral = generateEphemeralKeyPair();
                myEphemeralKeys.put(peer, ephemeral);
            }

            byte[] ephPubRaw = ephemeral.getPublic().getEncoded();
            String ephPubBase64 = Base64.getEncoder().encodeToString(ephPubRaw);
            byte[] signature = pki.sign(ephPubRaw);

            Message msg = new Message(ephPubBase64, "KEY");
            Packet hsPacket = new Packet(myId, "HANDSHAKE", 0, msg, peer.getAddress(), peer.getPort());
            hsPacket.setMac(Base64.getEncoder().encodeToString(signature));
            udpLink.send(hsPacket);

            System.out.println("[APL] Sent HANDSHAKE to " + peer);
        } catch (Exception e) {
            System.err.println("[APL] Failed to send HANDSHAKE to " + peer + ": " + e.getMessage());
            handshakeSent.remove(peer); // allow retry
        }
    }

    /** Called when a HANDSHAKE packet arrives from a peer. */
    private void handleHandshake(Packet p) {
        try {
            InetSocketAddress sender = new InetSocketAddress(p.getAddress(), p.getPort());

            // 1. Look up sender's node ID
            Integer peerId = peerIds.get(sender);
            if (peerId == null) {
                System.err.println("[APL] HANDSHAKE from unknown peer " + sender + " - dropping");
                return;
            }

            // 2. Decode ephemeral public key and verify ECDSA signature
            byte[] sig = Base64.getDecoder().decode(p.getAuthorship());
            byte[] keyBytes = Base64.getDecoder().decode(p.getMessage().getContent());
            if (!pki.verify(keyBytes, sig, peerId)) {
                System.err.println("[APL] Invalid HANDSHAKE signature from " + sender + " - dropping");
                return;
            }

            // Check if we already have an ephemeral key for this peer. If the key is the same, it's likely a duplicate HANDSHAKE
            // (e.g., due to retries) and we can ignore it. If the key is different, it indicates the peer has restarted and we should reset our session state.
            PublicKey existingKey = peerEphemeralKeys.get(sender);
            if (existingKey != null && java.util.Arrays.equals(existingKey.getEncoded(), keyBytes)) {
                if (sessionKeys.containsKey(sender)) {
                    // This is a duplicate HANDSHAKE with the same ephemeral key. Ignore it.
                    return; 
                }
            } else {
                // This is a new/different ephemeral key, indicating the peer restarted. Clear our
                // session state so werespond with a fresh HANDSHAKE and recompute the shared key.
                if (sessionKeys.remove(sender) != null) {
                    handshakeSent.remove(sender);
                    sessionLatches.remove(sender);
                    lowerBounds.remove(sender);
                    pendingBySeq.remove(sender);
                    gapWaitStartMs.remove(sender);
                    sequenceGenerators.remove(sender);
                    System.out.println("[APL] Peer " + sender + " re-initiated handshake — resetting session");
                }
            }

            // 3. Store the peer's ephemeral public key
            KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM);
            PublicKey peerEphPub = kf.generatePublic(new X509EncodedKeySpec(keyBytes));
            peerEphemeralKeys.put(sender, peerEphPub);

            // 4. Send our HANDSHAKE back if we haven't yet.
            //    To prevent infinite handshake loops when both sides initiate simultaneously,
            //    we use a deterministic tie-breaking rule: if we've already sent a HANDSHAKE
            //    to this peer (simultaneous initiation), only respond if our ID is lower.
            //    This ensures exactly one side takes the role of "responder" in such cases.
            boolean alreadySent = handshakeSent.contains(sender);
            if (!alreadySent || myId < peerId) {
                initiateHandshakeIfNeeded(sender);
            }

            // 5. Try to complete the session now that we have both ephemeral keys
            tryCompleteSession(sender);

        } catch (Exception e) {
            System.err.println("[APL] Error handling HANDSHAKE: " + e.getMessage());
        }
    }

    /** Completes the ECDH key agreement if both ephemeral keys are available. */
    private void tryCompleteSession(InetSocketAddress peer) {
        KeyPair myEph = myEphemeralKeys.get(peer);
        PublicKey peerEph = peerEphemeralKeys.get(peer);

        if (myEph == null || peerEph == null) return;
        if (sessionKeys.containsKey(peer)) return; // already done

        try {
            // ECDH key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(myEph.getPrivate());
            ka.doPhase(peerEph, true);
            byte[] sharedSecret = ka.generateSecret();

            // Derive HMAC key: SHA-256 of the raw shared secret
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hmacKeyBytes = sha256.digest(sharedSecret);
            String hmacKey = Base64.getEncoder().encodeToString(hmacKeyBytes);

            sessionKeys.put(peer, hmacKey);

            // Release any threads blocked in ensureSession()
            CountDownLatch latch = sessionLatches.get(peer);
            if (latch != null) latch.countDown();

            System.out.println("[APL] Session established with " + peer);

        } catch (Exception e) {
            System.err.println("[APL] ECDH session completion failed for " + peer + ": " + e.getMessage());
        }
    }

    private void startListenerThread() {
        Thread listener = new Thread(() -> {
            while (!udpLink.isClosed()) {
                try {
                    // Reception is handled by UDPLink
                    Packet packet = udpLink.receive();

                    // HANDSHAKE packets are processed before any HMAC check
                    if ("HANDSHAKE".equals(packet.getType())) {
                        handleHandshake(packet);
                        continue;
                    }

                    InetSocketAddress sender = new InetSocketAddress(packet.getAddress(), packet.getPort());
                    String sessionKey = sessionKeys.get(sender);

                    if (sessionKey == null) {
                        // No session yet; cannot verify — drop.
                        // But peer clearly has (or had) a session with us, so trigger
                        // a re-handshake so both sides can re-establish the key.
                        System.err.println("[APL] DATA/ACK from " + sender + " before session established - dropping");
                        if (peerIds.containsKey(sender)) {
                            // Force a new HANDSHAKE attempt immediately. Without this,
                            // one side may remain stuck believing a handshake is already
                            // in-flight while the peer keeps sending DATA.
                            handshakeSent.remove(sender);
                            sessionLatches.remove(sender);
                            initiateHandshakeIfNeeded(sender);
                        }
                        continue;
                    }

                    if (!packet.verify(sessionKey)) {
                        System.err.println("[APL] MAC verification failed from " + sender + " - dropping");
                        continue;
                    }

                    if ("ACK".equals(packet.getType())) {
                        handleAck(packet);
                    } else if ("DATA".equals(packet.getType())) {
                        handleData(packet, sender, sessionKey);
                    }

                } catch (Exception e) {
                    if (!udpLink.isClosed()) e.printStackTrace();
                }
            }
        });
        listener.setDaemon(true);
        listener.start();
    }

    private Object getReceiveLock(InetSocketAddress sender) {
        return receiveLocks.computeIfAbsent(sender, k -> new Object());
    }

    private void startGapTimeoutChecker() {
        gapTimeoutExecutor.scheduleAtFixedRate(() -> {
            if (udpLink.isClosed()) return;

            long now = System.currentTimeMillis();
            for (Map.Entry<InetSocketAddress, Long> entry : gapWaitStartMs.entrySet()) {
                InetSocketAddress sender = entry.getKey();
                long started = entry.getValue();
                if (now - started >= GAP_WAIT_TIMEOUT_MS) {
                    processGapTimeoutForSender(sender, now);
                }
            }
        }, 100, 100, TimeUnit.MILLISECONDS);
    }

    private void processGapTimeoutForSender(InetSocketAddress sender, long nowMs) {
        synchronized (getReceiveLock(sender)) {
            Integer expectedObj = lowerBounds.get(sender);
            ConcurrentHashMap<Integer, Packet> pending = pendingBySeq.get(sender);

            if (expectedObj == null || pending == null || pending.isEmpty()) {
                gapWaitStartMs.remove(sender);
                return;
            }

            int expected = expectedObj;
            Long started = gapWaitStartMs.get(sender);
            if (started == null || nowMs - started < GAP_WAIT_TIMEOUT_MS) {
                return;
            }

            int minPending = pending.keySet().stream()
                    .min(Integer::compareTo)
                    .orElse(expected);
            if (minPending > expected) {
                expected = minPending;
            }

            while (true) {
                Packet next = pending.remove(expected);
                if (next == null) break;
                try {
                    eventQueue.put(next);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                expected++;
            }

            lowerBounds.put(sender, expected);

            if (pending.isEmpty()) {
                gapWaitStartMs.remove(sender);
            } else if (pending.containsKey(expected)) {
                gapWaitStartMs.remove(sender);
            } else {
                gapWaitStartMs.put(sender, nowMs);
            }
        }
    }

    private void handleAck(Packet p) {
        // The ACK came from the original destination — that's the senderAddress of this packet
        InetSocketAddress sender = new InetSocketAddress(p.getAddress(), p.getPort());
        Map<Integer, AckMonitor> destMap = pendingAcks.get(sender);
        if (destMap == null) return;

        AckMonitor monitor = destMap.get(p.getSequenceNumber());
        if (monitor != null) {
            synchronized (monitor) {
                monitor.isAcknowledged = true;
                monitor.notify(); // wake the background send-worker immediately
            }
        }
    }

    private void handleData(Packet p, InetSocketAddress sender, String sessionKey) {
        int seq = p.getSequenceNumber();

        sendAck(p.getAddress(), p.getPort(), seq, sessionKey);

        synchronized (getReceiveLock(sender)) {
            lowerBounds.putIfAbsent(sender, 1);
            pendingBySeq.putIfAbsent(sender, new ConcurrentHashMap<>());

            int expected = lowerBounds.get(sender);
            ConcurrentHashMap<Integer, Packet> pending = pendingBySeq.get(sender);

            // On a fresh receiver/session, allow a controlled jump when the first
            // observed packet is far ahead. This handles peer restarts where old
            // sequence numbers are permanently missing.
            if (expected == 1 && pending.isEmpty() && seq >= 3) {
                expected = seq;
            }

            // Already delivered in the past.
            if (seq < expected) {
                return;
            }

            // Duplicate of a buffered packet.
            if (pending.putIfAbsent(seq, p) != null) {
                return;
            }

            // Deliver only contiguous packets in order: expected, expected+1, ...
            boolean deliveredAny = false;
            while (true) {
                Packet next = pending.remove(expected);
                if (next == null) break;
                try {
                    eventQueue.put(next);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                deliveredAny = true;
                expected++;
            }

            long now = System.currentTimeMillis();
            if (pending.isEmpty()) {
                gapWaitStartMs.remove(sender);
            } else if (pending.containsKey(expected)) {
                // There is no gap now; continue normal in-order delivery on next arrival.
                gapWaitStartMs.remove(sender);
            } else if (deliveredAny) {
                // We closed at least one gap and now hit a new one; start waiting for it.
                gapWaitStartMs.put(sender, now);
            } else {
                long started = gapWaitStartMs.computeIfAbsent(sender, k -> now);
                if (now - started >= GAP_WAIT_TIMEOUT_MS) {
                    int minPending = pending.keySet().stream()
                            .min(Integer::compareTo)
                            .orElse(expected);
                    if (minPending > expected) {
                        expected = minPending;
                    }

                    while (true) {
                        Packet next = pending.remove(expected);
                        if (next == null) break;
                        try {
                            eventQueue.put(next);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                        expected++;
                    }

                    if (pending.isEmpty() || pending.containsKey(expected)) {
                        gapWaitStartMs.remove(sender);
                    } else {
                        gapWaitStartMs.put(sender, now);
                    }
                }
            }

            lowerBounds.put(sender, expected);
        }
    }

    private void sendAck(InetAddress destIp, int destPort, int sequenceNumber, String sessionKey) {
        if (udpLink.isClosed()) return;
        try {
            Packet ack = new Packet(myId,"ACK", sequenceNumber, new Message("", "ACK"), destIp, destPort);
            ack.sign(sessionKey);
            udpLink.send(ack);
        } catch (Exception e) {
            if (udpLink.isClosed()) {
                return;
            }
            System.err.println("[APL] Failed to send ACK: " + e.getMessage());
        }
    }

    /** Generates a fresh ephemeral EC key pair for the handshake. */
    private static KeyPair generateEphemeralKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
        kpg.initialize(new ECGenParameterSpec(EC_CURVE));
        return kpg.generateKeyPair();
    }
}
