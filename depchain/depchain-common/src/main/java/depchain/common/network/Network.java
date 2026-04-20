package depchain.common.network;

import java.net.InetAddress;

/**
 * Minimal abstraction over the reliable, authenticated point-to-point link.
 *
 * Extracting this interface allows consensus logic to be tested with an
 * in-memory stub without spinning up real UDP sockets.
 */
public interface Network {
    /**
     * Sends msg to code (destIp, destPort).
     * The call is non-blocking; delivery is best-effort from the caller's
     * perspective (the concrete implementation handles retransmission).
     */
    void send(InetAddress destIp, int destPort, Message msg);
}
