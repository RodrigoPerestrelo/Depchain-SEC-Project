package depchain.node.consensus;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;
import depchain.common.utils.StaticMembership;
import depchain.node.crypto.ThresholdSignatureService;
import depchain.node.state.ServiceState;
import depchain.node.state.UpcallHandler;
import depchain.node.consensus.QuorumCertificate;

import org.junit.jupiter.api.*;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end algorithm correctness tests for BasicHotStuff.
 *
 * Setup: n=4 replicas, f=1 (quorum=3). Real threshold key material is
 * generated once per class into a temp directory so every test exercises
 * genuine threshold signatures.
 *
 * Network model: InMemoryBus replaces real UDP, routes messages between
 * instances in the same JVM with a small (20 ms) propagation delay.
 * Individual nodes can be silenced (all incoming messages dropped) to
 * simulate crashes or leader failures.
 *
 * Scenarios:
 *   1. happyPath                          -- normal single-command decision
 *   2. multipleSequentialCommands         -- three consecutive decisions in order
 *   3. oneNodeCrash                       -- one replica down, quorum still met
 *   4. leaderFailureTriggerViewChange     -- leader of view 1 dead; view-change to view 2
 *   5. clientResponseDeliveredAfterDecision -- CLIENT_RESPONSE forwarded after consensus
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HotStuffClusterTest {

    // ── Cluster constants ──────────────────────────────────────────────────────
    static final int N        = 4;
    static final int F        = 1;
    static final int K        = 2 * F + 1;   // quorum / threshold = 3
    static final int KEY_BITS = 512;          // small key for speed
    static final int[] PORTS  = { 9000, 9001, 9002, 9003 };
    static final String DEFAULT_TO = "0x0000000000000000000000000000000000000001";
    static final long DEFAULT_GAS_LIMIT = 30000L;
    static final long DEFAULT_GAS_PRICE = 1L;

    // ── Test-5 client constants ────────────────────────────────────────────────
    static final int CLIENT_ID_FOR_TEST5   = 4;
    static final int CLIENT_PORT_FOR_TEST5 = 19999;

    // ── Shared key material (generated once) ──────────────────────────────────
    static Path          tempKeysDir;
    static PKIProvider[] pkis;

    // ── Per-test cluster ──────────────────────────────────────────────────────
    Cluster cluster;

    // =========================================================================
    // Key generation
    // =========================================================================

    @BeforeAll
    static void generateKeyMaterial() throws Exception {
        tempKeysDir = Files.createTempDirectory("hotstuff-test-");
        System.out.printf("%n[setup] Key directory: %s%n", tempKeysDir);
        long t = System.currentTimeMillis();
        PKIProvider.generateKeys(tempKeysDir.toString(), N);
        PKIProvider.generateThresholdKeys(tempKeysDir.toString(), K, N, KEY_BITS);
        pkis = new PKIProvider[N];
        for (int i = 0; i < N; i++) pkis[i] = new PKIProvider(tempKeysDir.toString(), i, N);
        System.out.printf("[setup] Keys ready in %d ms  (k=%d l=%d bits=%d)%n",
                System.currentTimeMillis() - t, K, N, KEY_BITS);
    }

    @AfterAll
    static void cleanUpKeys() throws IOException {
        if (tempKeysDir != null && Files.exists(tempKeysDir))
            Files.walk(tempKeysDir).sorted(Comparator.reverseOrder())
                 .forEach(p -> { try { Files.delete(p); } catch (IOException ignored) {} });
    }

    @BeforeEach void setUp()    { cluster = new Cluster(); }
    @AfterEach  void tearDown() { cluster.shutdown(); }

    // =========================================================================
    // Test 1 – Happy path: all nodes correct, single command
    // =========================================================================

    @Test @Order(1) @Timeout(18)
    void happyPath() throws Exception {
        System.out.println("\n══════════  TEST 1: happyPath  ══════════");

        cluster.startAll();

        // leader(1) = 1 % 4 = 1
        ClientRequest req = buildRequest(1, 1, "block-1");
        int  leader = cluster.membership.getLeader(1);
        cluster.proposeAt(leader, req);

        long t = System.currentTimeMillis();
        for (int i = 0; i < N; i++) {
            String cmd = cluster.awaitDecision(i, 14_000);
            System.out.printf("  node %d decided '%s' in %d ms%n",
                    i, cmd, System.currentTimeMillis() - t);
            assertEquals(toHex("block-1"), cmd, "node " + i + " wrong decision");
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 2 – Multiple sequential commands
    // =========================================================================

    @Test @Order(2) @Timeout(60)
    void multipleSequentialCommands() throws Exception {
        System.out.println("\n══════════  TEST 2: multipleSequentialCommands  ══════════");

        // Pre-load one command per view leader so the right node proposes it
        // leader(v) = v % 4
        String[] cmds     = { "tx-Alice", "tx-Bob", "tx-Carol" };
        int[]    leaders  = { 1, 2, 3 };   // views 1, 2, 3
        ClientRequest cmdReq;
        for (int i = 0; i < cmds.length; i++) {
            cmdReq = buildRequest(i + 1, i + 1, cmds[i]);
            cluster.proposeAt(leaders[i], cmdReq);
        }
        cluster.startAll();

        long t = System.currentTimeMillis();
        for (String expected : cmds) {
            System.out.printf("  waiting for '%s'...%n", expected);
            for (int i = 0; i < N; i++) {
                String got = cluster.awaitDecision(i, 14_000);
                System.out.printf("    node %d: '%s'  (%d ms)%n",
                        i, got, System.currentTimeMillis() - t);
                assertEquals(toHex(expected), got, "out-of-order or wrong decision at node " + i);
            }
            Thread.sleep(100);  // let all nodes stabilise before next round
        }
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 3 – One node crash (f = 1 tolerated)
    // =========================================================================

    @Test @Order(3) @Timeout(18)
    void oneNodeCrash() throws Exception {
        System.out.println("\n══════════  TEST 3: oneNodeCrash  ══════════");

        ClientRequest req = buildRequest(1, 1, "crash-tx");
        cluster.proposeAt(cluster.membership.getLeader(1), req);
        cluster.startAll();
        cluster.silence(3);   // node 3 goes offline after startup
        System.out.println("  node 3 silenced");

        long t = System.currentTimeMillis();
        // Nodes 0, 1, 2 form the quorum; they must all decide
        for (int i = 0; i < N - 1; i++) {
            String cmd = cluster.awaitDecision(i, 14_000);
            System.out.printf("  node %d decided '%s' in %d ms%n",
                    i, cmd, System.currentTimeMillis() - t);
            assertEquals(toHex("crash-tx"), cmd, "node " + i + " wrong decision with crash");
        }

        // Silenced node must NOT appear in results
        String node3 = cluster.pollDecision(3, 600);
        assertNull(node3, "silenced node 3 must not decide");
        System.out.println("  node 3 correctly silent ✓");
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 4 – Leader of view 1 never starts -> view change -> view 2 decides
    // =========================================================================

    @Test @Order(4) @Timeout(28)
    void leaderFailureTriggerViewChange() throws Exception {
        System.out.println("\n══════════  TEST 4: leaderFailureTriggerViewChange  ══════════");

        int leaderV1 = cluster.membership.getLeader(1);  // = 1
        int leaderV2 = cluster.membership.getLeader(2);  // = 2
        System.out.printf("  leader(view1)=%d  leader(view2)=%d%n", leaderV1, leaderV2);

        // Pre-load command on ALL alive nodes (mirrors production: client
        // broadcasts to every node).  The dead leader never receives it.
        ClientRequest cmd_req = buildRequest(1, 1, "post-viewchange-tx");
        for (int i = 0; i < N; i++)
            if (i != leaderV1) cluster.proposeAt(i, cmd_req);

        // Start all nodes EXCEPT the view-1 leader — it's "dead"
        cluster.startExcept(leaderV1);
        System.out.printf("  node %d NOT started (leader of view 1 is down)%n", leaderV1);
        System.out.println("  waiting for view-timeout (~4 s) + view-2 consensus...");

        long t = System.currentTimeMillis();
        for (int i = 0; i < N; i++) {
            if (i == leaderV1) continue;
            String cmd     = cluster.awaitDecision(i, 22_000);
            long   elapsed = System.currentTimeMillis() - t;
            System.out.printf("  node %d decided '%s' in %d ms%n", i, cmd, elapsed);
            assertEquals(toHex("post-viewchange-tx"), cmd, "node " + i + " wrong decision after view change");
        }

        long elapsed = System.currentTimeMillis() - t;
        assertTrue(elapsed >= 3_000,
            "View change should have taken a substantial timeout interval (was " + elapsed + " ms)");
        System.out.println("  view-change correctly waited for timeout ✓");
        System.out.println("  PASS ✓");
    }

    // =========================================================================
    // Test 5 – CLIENT_RESPONSE is sent to the client after consensus decides
    //           a ClientRequest JSON command
    // =========================================================================

    @Test @Order(5) @Timeout(18)
    void clientResponseDeliveredAfterDecision() throws Exception {
        System.out.println("\n══════════  TEST 5: clientResponseDeliveredAfterDecision  ══════════");

        StaticMembership membership = buildMembershipWithClient();
        // Use InMemoryBus with client-port capture
        InMemoryBus bus = new InMemoryBus(membership, 20, CLIENT_PORT_FOR_TEST5);

        ClientResponseRecordingHandler[] handlers = new ClientResponseRecordingHandler[N];
        BasicHotStuff[] hsNodes = new BasicHotStuff[N];
        for (int i = 0; i < N; i++) {
            handlers[i] = new ClientResponseRecordingHandler(bus, membership, i);
            hsNodes[i]  = new BasicHotStuff(membership, i, bus,
                    new ThresholdSignatureService(pkis[i], i), handlers[i]);
            bus.register(i, hsNodes[i]);
        }

        // Leader of view 1 proposes a ClientRequest JSON command
        int leader   = membership.getLeader(1);
        int reqId = 1;
        ClientRequest reqJson = buildRequest(CLIENT_ID_FOR_TEST5, reqId, "hello-from-client");
        hsNodes[leader].proposeCommand(reqJson);

        for (BasicHotStuff n : hsNodes) n.start();

        try {
            long t = System.currentTimeMillis();

            // All N nodes must decide
            for (int i = 0; i < N; i++) {
                String decided = handlers[i].decided.poll(14_000, TimeUnit.MILLISECONDS);
                assertNotNull(decided, "node " + i + " must decide");
                System.out.printf("  node %d decided in %d ms%n",
                        i, System.currentTimeMillis() - t);
            }

            // Each deciding node sends one CLIENT_RESPONSE to the client port.
            // Collect up to N responses; require at least 2f+1 (quorum).
            int responseCount = 0;
            for (int i = 0; i < N; i++) {
                Message msg = bus.clientMessages.poll(2_000, TimeUnit.MILLISECONDS);
                if (msg == null) break;
                assertEquals("CLIENT_RESPONSE", msg.getType());
                ClientResponse resp = ClientResponse.fromJson(msg.getContent());
                assertEquals(reqId, resp.getRequestId(),
                        "requestId must match the submitted request");
                assertTrue(
                    resp.getResult().startsWith("EVM_TX_SUCCESS")
                        || resp.getResult().startsWith("EXECUTION FAILED"),
                    "result must indicate either success or execution failure");
                responseCount++;
            }

            assertTrue(responseCount >= 2 * F + 1,
                    "At least 2f+1=" + (2 * F + 1) + " CLIENT_RESPONSE messages required; got " + responseCount);
            System.out.printf("  received %d CLIENT_RESPONSE(s) ✓%n", responseCount);
            System.out.println("  PASS ✓");

        } finally {
            for (BasicHotStuff n : hsNodes) n.shutdown();
        }
    }

    // =========================================================================
    // Infrastructure — Cluster
    // =========================================================================

    final class Cluster {
        final StaticMembership          membership;
        final InMemoryBus               bus;
        final BasicHotStuff[]           nodes;
        final RecordingUpcallHandler[]  handlers;

        Cluster() {
            membership = buildMembership();
            bus        = new InMemoryBus(membership, 20 /* ms */);
            nodes      = new BasicHotStuff[N];
            handlers   = new RecordingUpcallHandler[N];
            for (int i = 0; i < N; i++) {
                handlers[i] = new RecordingUpcallHandler(membership, i);
                nodes[i]    = new BasicHotStuff(membership, i, bus,
                        new ThresholdSignatureService(pkis[i], i), handlers[i]);
                bus.register(i, nodes[i]);
            }
        }

        void startAll() {
            for (BasicHotStuff n : nodes) n.start();
        }

        void startExcept(int skip) {
            for (int i = 0; i < N; i++) if (i != skip) nodes[i].start();
        }

        void proposeAt(int nodeId, ClientRequest cmd) { nodes[nodeId].proposeCommand(cmd); }
        void silence(int id)  { bus.silence(id); }
        void restore(int id)  { bus.restore(id); }

        String awaitDecision(int id, long ms) throws InterruptedException {
            return handlers[id].decided.poll(ms, TimeUnit.MILLISECONDS);
        }

        String pollDecision(int id, long ms) throws InterruptedException {
            return handlers[id].decided.poll(ms, TimeUnit.MILLISECONDS);
        }

        void shutdown() { for (BasicHotStuff n : nodes) n.shutdown(); }
    }

    // =========================================================================
    // Infrastructure — InMemoryBus
    // =========================================================================

    static class InMemoryBus implements Network {
        private final StaticMembership             membership;
        private final long                         delayMs;
        private final int                          clientPort;   // -1 = no client capture
        final         BlockingQueue<Message>       clientMessages = new LinkedBlockingQueue<>();
        private final Map<Integer, BasicHotStuff>  routing  = new ConcurrentHashMap<>();
        private final Set<Integer>                 silenced = ConcurrentHashMap.newKeySet();
        private final ExecutorService              pool     = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "bus");
            t.setDaemon(true);
            return t;
        });

        InMemoryBus(StaticMembership m, long delayMs) {
            this(m, delayMs, -1);
        }

        InMemoryBus(StaticMembership m, long delayMs, int clientPort) {
            this.membership  = m;
            this.delayMs     = delayMs;
            this.clientPort  = clientPort;
        }

        void register(int id, BasicHotStuff n) { routing.put(id, n); }
        void silence(int id)  { silenced.add(id); }
        void restore(int id)  { silenced.remove(id); }

        @Override
        public void send(InetAddress destIp, int destPort, Message msg) {
            // Capture messages destined for the mock client
            if (clientPort > 0 && destPort == clientPort) {
                clientMessages.offer(msg);
                return;
            }

            Integer destId = portToId(destPort);
            if (destId == null || silenced.contains(destId)) return;
            BasicHotStuff target = routing.get(destId);
            if (target == null) return;

            HotStuffMessage hm = HotStuffMessage.fromJson(msg.getContent());
            if (delayMs <= 0) {
                target.addMessageToQueue(hm);
            } else {
                pool.submit(() -> {
                    try { Thread.sleep(delayMs); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                    target.addMessageToQueue(hm);
                });
            }
        }

        private Integer portToId(int port) {
            for (StaticMembership.NodeInfo ni : membership.getAllNodes())
                if (ni.getPort() == port) return ni.getId();
            return null;
        }
    }

    // =========================================================================
    // Infrastructure — RecordingUpcallHandler
    // =========================================================================

    static final class RecordingUpcallHandler extends UpcallHandler {
        final BlockingQueue<String> decided = new LinkedBlockingQueue<>();

        RecordingUpcallHandler(StaticMembership membership, int nodeId) {
            super(new ServiceState(), null, membership, nodeId, null);
        }

        @Override
        public void execute(ClientRequest req, QuorumCertificate commitQC, boolean sendReply) {
            super.execute(req, commitQC, sendReply);

            if (req != null) {
                decided.offer(req.getData());
            }
        }
    }

    // =========================================================================
    // Infrastructure — ClientResponseRecordingHandler
    // Extends UpcallHandler with the full network constructor so that
    // CLIENT_RESPONSE messages are forwarded to the InMemoryBus (Test 5).
    // =========================================================================

    static final class ClientResponseRecordingHandler extends UpcallHandler {
        final BlockingQueue<String> decided = new LinkedBlockingQueue<>();

        ClientResponseRecordingHandler(Network net, StaticMembership membership, int nodeId) {
            super(new ServiceState(), net, membership, nodeId, null);
        }

        @Override
        public void execute(ClientRequest req, QuorumCertificate commitQC, boolean sendReply) {
            super.execute(req, commitQC, sendReply);

            if (req != null) {
                decided.offer(req.getData());
            }
        }
    }

    private static ClientRequest buildRequest(int clientId, int requestId, String dataText) {
        return new ClientRequest(
                clientId,
                requestId,
                DEFAULT_TO,
                0L,
                DEFAULT_GAS_LIMIT,
                DEFAULT_GAS_PRICE,
                toHex(dataText),
                System.currentTimeMillis());
    }

    private static String toHex(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder("0x");
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // =========================================================================

    static StaticMembership buildMembership() {
        List<StaticMembership.NodeInfo> ns = new ArrayList<>();
        for (int i = 0; i < N; i++)
            ns.add(new StaticMembership.NodeInfo(i, "127.0.0.1", PORTS[i]));
        return new StaticMembership(F, ns);
    }

    /** Membership that includes a mock client for Test 5. */
    static StaticMembership buildMembershipWithClient() {
        List<StaticMembership.NodeInfo> nodes   = new ArrayList<>();
        List<StaticMembership.NodeInfo> clients = new ArrayList<>();
        for (int i = 0; i < N; i++)
            nodes.add(new StaticMembership.NodeInfo(i, "127.0.0.1", PORTS[i]));
        clients.add(new StaticMembership.NodeInfo(CLIENT_ID_FOR_TEST5,
                "127.0.0.1", CLIENT_PORT_FOR_TEST5));
        return new StaticMembership(F, nodes, clients);
    }
}

