package depchain.common.test;

import depchain.common.network.UDPLink;
import depchain.common.network.Packet;
import depchain.common.network.Message;
import java.net.InetAddress;

/**
 * Manual test for raw UDPLink send/receive without the APL layer.
 */
public class SimpleUDPTest {
    
    public static void main(String[] args) {
        try {
            if (args.length != 1) {
                System.out.println("Usage: java SimpleUDPTest <receiver|sender>");
                return;
            }
            
            String mode = args[0];
            
            if ("receiver".equals(mode)) {
                // Simple receiver
                System.out.println("Simple UDP receiver on port 8001...");
                UDPLink udp = new UDPLink(8001);

                while (true) {
                    System.out.println("Waiting for packet...");
                    Packet p = udp.receive();
                    System.out.println("Received: " + p.getType() + " | " + p.getMessage().getContent() + " | from " + p.getAddress() + ":" + p.getPort());
                }
                
            } else if ("sender".equals(mode)) {
                // Simple sender
                System.out.println("Simple UDP sender on port 8002...");
                UDPLink udp = new UDPLink(8002);

                Packet packet = new Packet(0, "TEST", 1, new Message("Hello UDP!", "DATA"), InetAddress.getByName("127.0.0.1"), 8001);
                System.out.println("Sending packet to localhost:8001");
                udp.send(packet);
                System.out.println("Packet sent!");
                
                Thread.sleep(1000);
                udp.close();
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}