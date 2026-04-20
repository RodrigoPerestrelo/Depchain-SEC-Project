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

@DisplayName("Bidirectional authenticated communication")
class TestBidirectionalTest {

    @Test
    @DisplayName("Both nodes exchange 3 messages and receive all with correct content")
    void testBidirectional() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp0 = kpg.generateKeyPair();
        KeyPair kp1 = kpg.generateKeyPair();

        Map<Integer, PublicKey> pubKeys = new HashMap<>();
        pubKeys.put(0, kp0.getPublic());
        pubKeys.put(1, kp1.getPublic());

        InetAddress localhost = InetAddress.getByName("127.0.0.1");
        int port0 = 8001, port1 = 8002;

        Map<InetSocketAddress, Integer> peersOf0 = new HashMap<>();
        peersOf0.put(new InetSocketAddress(localhost, port1), 1);

        Map<InetSocketAddress, Integer> peersOf1 = new HashMap<>();
        peersOf1.put(new InetSocketAddress(localhost, port0), 0);

        PKIProvider pki0 = new PKIProvider(kp0.getPrivate(), pubKeys);
        PKIProvider pki1 = new PKIProvider(kp1.getPrivate(), pubKeys);
        AuthenticatedPerfectLinks apl0 = new AuthenticatedPerfectLinks(port0, 0, pki0, peersOf0);
        AuthenticatedPerfectLinks apl1 = new AuthenticatedPerfectLinks(port1, 1, pki1, peersOf1);

        List<String> received0 = new CopyOnWriteArrayList<>();
        List<String> received1 = new CopyOnWriteArrayList<>();

        Thread r0 = new Thread(() -> {
            while (received0.size() < 3) {
                try {
                    received0.add(apl0.deliver().getContent());
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "receiver-0");

        Thread r1 = new Thread(() -> {
            while (received1.size() < 3) {
                try {
                    received1.add(apl1.deliver().getContent());
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "receiver-1");

        r0.setDaemon(true);
        r1.setDaemon(true);
        r0.start();
        r1.start();

        Thread.sleep(500);

        for (int i = 1; i <= 3; i++) {
            apl0.send(localhost, port1, new Message("From Node 0 #" + i, "DATA"));
            apl1.send(localhost, port0, new Message("From Node 1 #" + i, "DATA"));
            Thread.sleep(200);
        }

        r0.join(15_000);
        r1.join(15_000);

        apl0.close();
        apl1.close();

        assertAll("Bidirectional delivery",
            () -> assertFalse(r0.isAlive(), "Receiver 0 did not finish within timeout"),
            () -> assertFalse(r1.isAlive(), "Receiver 1 did not finish within timeout"),
            () -> assertEquals(3, received0.size(), "Node 0 should receive exactly 3 messages"),
            () -> assertEquals(3, received1.size(), "Node 1 should receive exactly 3 messages"),
            () -> assertTrue(received0.contains("From Node 1 #1"), "Node 0 missing 'From Node 1 #1'"),
            () -> assertTrue(received0.contains("From Node 1 #2"), "Node 0 missing 'From Node 1 #2'"),
            () -> assertTrue(received0.contains("From Node 1 #3"), "Node 0 missing 'From Node 1 #3'"),
            () -> assertTrue(received1.contains("From Node 0 #1"), "Node 1 missing 'From Node 0 #1'"),
            () -> assertTrue(received1.contains("From Node 0 #2"), "Node 1 missing 'From Node 0 #2'"),
            () -> assertTrue(received1.contains("From Node 0 #3"), "Node 1 missing 'From Node 0 #3'")
        );
    }
}
