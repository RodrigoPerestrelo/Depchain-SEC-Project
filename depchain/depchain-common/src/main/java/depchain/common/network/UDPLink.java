package depchain.common.network;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;

/**
 * Thin abstraction over a UDP DatagramSocket for sending and receiving
 * JSON-serialized Packet instances.
 */
public class UDPLink {

    private final DatagramSocket socket;
    private static final int MAX_DATAGRAM_SIZE = 65535;

    /**
     * @param sourcePort the local port to bind to
     * @throws IOException if the socket cannot be created
     */
    public UDPLink(Integer sourcePort) throws IOException {
        this.socket = new DatagramSocket(sourcePort);
    }

    /**
     * Sends a packet to its destination address and port.
     *
     * @param packet the packet to send
     * @throws IOException if the send fails
     */
    public void send(Packet packet) throws IOException {
        String formattedPacket = packet.formatPacket();
        byte[] fullData = formattedPacket.getBytes(StandardCharsets.UTF_8);

        DatagramPacket resultPacket = new DatagramPacket(fullData, fullData.length, packet.getAddress(), packet.getPort());
        this.socket.send(resultPacket);
    }

    /**
     * Blocks until a packet is received. The returned packet contains the
     * sender's address/port and the original MAC from the wire.
     *
     * @return the received packet
     * @throws IOException if the receive fails
     */
    public Packet receive() throws IOException {
        byte[] buffer = new byte[MAX_DATAGRAM_SIZE];
        DatagramPacket udpPacket = new DatagramPacket(buffer, buffer.length);
        
        this.socket.receive(udpPacket);

        String json = new String(udpPacket.getData(), 0, udpPacket.getLength(), StandardCharsets.UTF_8);
        Packet p = Packet.fromJson(json);

        // Overwrite with the actual sender address/port from the UDP datagram
        p.setAddress(udpPacket.getAddress());
        p.setPort(udpPacket.getPort());
        return p;
    }

    /** Closes the underlying socket if it is open. */
    public void close() {
        if (this.socket != null && !this.socket.isClosed()) {
            this.socket.close();
        }
    }

    /** Returns true if the socket has been closed. */
    public boolean isClosed() {
        return this.socket.isClosed();
    }
}