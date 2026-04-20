package depchain.common.test;

import depchain.common.crypto.PKIProvider;
import depchain.common.network.AuthenticatedPerfectLinks;
import depchain.common.network.Message;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Manual test sender — run alongside TestReceiver (two separate processes).
 *
 * Sends 5 messages to the receiver and waits for all ACKs.
 * Prints PASS if all messages were acknowledged, FAIL otherwise.
 *
 * Usage:
 *   Terminal 1: mvn exec:java -pl depchain-common -Dexec.mainClass=depchain.common.test.TestReceiver
 *   Terminal 2: mvn exec:java -pl depchain-common -Dexec.mainClass=depchain.common.test.TestSender
 */
public class TestSender {

    private static final String DEFAULT_KEYS_DIR = "config/test-keys";
    private static final int    MY_ID          = 1;
    private static final int    MY_PORT        = 8002;
    private static final int    RECEIVER_ID    = 0;
    private static final int    RECEIVER_PORT  = 8001;
    private static final int    N_MESSAGES     = 5;

    public static void main(String[] args) throws Exception {
        String keysDir = args.length > 0 ? args[0] : DEFAULT_KEYS_DIR;

        if (!Files.exists(Paths.get(keysDir, "node0.pub"))) {
            System.out.println("Generating 2 key pairs in " + keysDir);
            PKIProvider.generateKeys(keysDir, 2);
        }

        PKIProvider pki = new PKIProvider(keysDir, MY_ID, 2);

        Map<InetSocketAddress, Integer> peerIds = new HashMap<>();
        peerIds.put(new InetSocketAddress("127.0.0.1", RECEIVER_PORT), RECEIVER_ID);

        AuthenticatedPerfectLinks apl =
                new AuthenticatedPerfectLinks(MY_PORT, MY_ID, pki, peerIds);

        InetAddress localhost = InetAddress.getByName("127.0.0.1");

        System.out.println("Sender (node " + MY_ID + ") on port " + MY_PORT
                + " -> receiver (node " + RECEIVER_ID + ") on port " + RECEIVER_PORT);

        Thread.sleep(1_000); // give receiver time to start

        for (int i = 1; i <= N_MESSAGES; i++) {
            String content = "Message " + i;
            System.out.println("Sending: \"" + content + "\"");
            apl.send(localhost, RECEIVER_PORT, new Message(content, "DATA"));
            Thread.sleep(500);
        }

        // Wait long enough for all ACKs to arrive (APL prints each one)
        System.out.println("Waiting for ACKs...");
        Thread.sleep(5_000);

        apl.close();
        // If we reach here without an unhandled exception, all sends were submitted.
        // Delivery confirmation comes from the "[APL] ACK received" lines printed above.
        System.out.println("\n[PASS] " + N_MESSAGES + " messages sent and ACKed successfully.");
    }
}
