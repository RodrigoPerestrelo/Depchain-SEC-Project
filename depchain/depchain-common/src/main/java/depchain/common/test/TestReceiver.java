package depchain.common.test;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.AuthenticatedPerfectLinks;
import depchain.common.network.Message;

import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Manual test receiver — run alongside TestSender (two separate processes).
 *
 * Expects exactly 5 messages ("Message 1" … "Message 5") from the sender.
 * Prints PASS/FAIL once all expected messages have been received.
 *
 * Usage:
 *   Terminal 1: mvn exec:java -pl depchain-common -Dexec.mainClass=depchain.common.test.TestReceiver
 *   Terminal 2: mvn exec:java -pl depchain-common -Dexec.mainClass=depchain.common.test.TestSender
 */
public class TestReceiver {

    private static final String DEFAULT_KEYS_DIR = "config/test-keys";
    private static final int MY_ID       = 0;
    private static final int MY_PORT     = 8001;
    private static final int SENDER_ID   = 1;
    private static final int SENDER_PORT = 8002;
    private static final int N_MESSAGES  = 5;

    public static void main(String[] args) throws Exception {
        String keysDir = args.length > 0 ? args[0] : DEFAULT_KEYS_DIR;

        if (!Files.exists(Paths.get(keysDir, "node0.pub"))) {
            System.out.println("Generating 2 key pairs in " + keysDir);
            PKIProvider.generateKeys(keysDir, 2);
        }

        PKIProvider pki = new PKIProvider(keysDir, MY_ID, 2);

        Map<InetSocketAddress, Integer> peerIds = new HashMap<>();
        peerIds.put(new InetSocketAddress("127.0.0.1", SENDER_PORT), SENDER_ID);

        AuthenticatedPerfectLinks apl =
                new AuthenticatedPerfectLinks(MY_PORT, MY_ID, pki, peerIds);

        System.out.println("Receiver (node " + MY_ID + ") on port " + MY_PORT
                + " — expecting " + N_MESSAGES + " messages from node " + SENDER_ID);

        List<String> received = new ArrayList<>();
        while (received.size() < N_MESSAGES) {
            Message msg = apl.deliver();
            received.add(msg.getContent());
            System.out.printf("[%d/%d] Received: \"%s\"%n",
                    received.size(), N_MESSAGES, msg.getContent());
        }

        // --- Assertions ---
        System.out.println("\n--- Results ---");
        int failures = 0;

        if (received.size() == N_MESSAGES) {
            System.out.println("  [PASS] Received exactly " + N_MESSAGES + " messages");
        } else {
            System.err.println("  [FAIL] Expected " + N_MESSAGES + " messages, got " + received.size());
            failures++;
        }

        for (int i = 1; i <= N_MESSAGES; i++) {
            String expected = "Message " + i;
            if (received.contains(expected)) {
                System.out.println("  [PASS] Received \"" + expected + "\"");
            } else {
                System.err.println("  [FAIL] Missing \"" + expected + "\"");
                failures++;
            }
        }

        apl.close();
        System.out.println(failures == 0 ? "\nPASS" : "\nFAIL (" + failures + " check(s) failed)");
        System.exit(failures == 0 ? 0 : 1);
    }
}
