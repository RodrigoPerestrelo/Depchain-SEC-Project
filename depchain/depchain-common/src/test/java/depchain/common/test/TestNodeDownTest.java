package depchain.common.test;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.AuthenticatedPerfectLinks;
import depchain.common.network.Message;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("APL reliability under node failure")
class TestNodeDownTest {

    private static final int PORT_0 = 8010;
    private static final int PORT_1 = 8011;
    // retries > 5 in APL, 500 ms each -> at least 3 000 ms before session is cleared
    private static final long RETRY_DRAIN_MS = 4_000;

    @Test
    @DisplayName("Retries on peer down, drops after max retries, reconnects after peer restart")
    void testNodeDown() throws Exception {
        InetAddress localhost = InetAddress.getByName("127.0.0.1");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp0 = kpg.generateKeyPair();
        KeyPair kp1 = kpg.generateKeyPair();

        Map<Integer, PublicKey> pubKeys = new HashMap<>();
        pubKeys.put(0, kp0.getPublic());
        pubKeys.put(1, kp1.getPublic());

        PKIProvider pki0 = new PKIProvider(kp0.getPrivate(), pubKeys);
        PKIProvider pki1 = new PKIProvider(kp1.getPrivate(), pubKeys);

        Map<InetSocketAddress, Integer> peersOf0 = new HashMap<>();
        peersOf0.put(new InetSocketAddress(localhost, PORT_1), 1);

        Map<InetSocketAddress, Integer> peersOf1 = new HashMap<>();
        peersOf1.put(new InetSocketAddress(localhost, PORT_0), 0);

        // --- Phase 1: Normal operation ---
        AuthenticatedPerfectLinks apl0 = new AuthenticatedPerfectLinks(PORT_0, 0, pki0, peersOf0);
        AuthenticatedPerfectLinks apl1 = new AuthenticatedPerfectLinks(PORT_1, 1, pki1, peersOf1);

        List<String> phase1 = new CopyOnWriteArrayList<>();
        Thread r1 = receiverThread(apl1, phase1, 2);
        r1.start();
        Thread.sleep(300);

        apl0.send(localhost, PORT_1, new Message("Message #1 (before crash)", "DATA"));
        apl0.send(localhost, PORT_1, new Message("Message #2 (before crash)", "DATA"));
        r1.join(5_000);

        assertAll("Phase 1 — normal delivery",
            () -> assertEquals(2, phase1.size(), "Node 1 should receive exactly 2 messages"),
            () -> assertTrue(phase1.contains("Message #1 (before crash)"), "Missing message #1"),
            () -> assertTrue(phase1.contains("Message #2 (before crash)"), "Missing message #2")
        );

        // --- Phase 2: Node 1 crashes ---
        apl1.close();
        r1.interrupt();

        // --- Phase 3: Retries until max, session state cleared ---
        List<String> phase3 = new CopyOnWriteArrayList<>();
        apl0.send(localhost, PORT_1, new Message("Message #3 (will be dropped)", "DATA"));
        apl0.send(localhost, PORT_1, new Message("Message #4 (will be dropped)", "DATA"));
        Thread.sleep(RETRY_DRAIN_MS);

        assertTrue(phase3.isEmpty(),
                "Phase 3: messages #3 and #4 must NOT be delivered while node is down");

        // --- Phase 4: Node 1 restarts — automatic reconnection ---
        AuthenticatedPerfectLinks apl1new =
                new AuthenticatedPerfectLinks(PORT_1, 1, pki1, peersOf1);

        List<String> phase4 = new CopyOnWriteArrayList<>();
        Thread r1new = receiverThread(apl1new, phase4, 1);
        r1new.start();
        Thread.sleep(300);

        apl0.send(localhost, PORT_1, new Message("Message #5 (after reconnect)", "DATA"));
        r1new.join(5_000);

        apl0.close();
        apl1new.close();
        r1new.interrupt();

        assertAll("Phase 4 — automatic reconnection",
            () -> assertEquals(1, phase4.size(),
                    "Node 1 (restarted) should receive exactly 1 message after reconnect"),
            () -> assertTrue(phase4.contains("Message #5 (after reconnect)"),
                    "Missing message #5 after reconnect")
        );
    }

    private static Thread receiverThread(AuthenticatedPerfectLinks apl,
                                          List<String> collected, int limit) {
        Thread t = new Thread(() -> {
            while (collected.size() < limit && !Thread.currentThread().isInterrupted()) {
                try {
                    collected.add(apl.deliver().getContent());
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        t.setDaemon(true);
        return t;
    }
}
