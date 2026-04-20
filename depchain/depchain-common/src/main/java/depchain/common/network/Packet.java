package depchain.common.network;

import java.net.InetAddress;
import java.util.Base64;

import com.google.gson.Gson;

import depchain.common.crypto.Hasher;

/**
 * Network packet with MAC-based authentication.
 * Supports serialization to/from JSON for transport over UDP.
 */
public class Packet{
    private static final Gson gson = new Gson();

    private String type;
    private Message content;
    private String mac;
    private int sequenceNumber;
    private InetAddress Address;  // destination address
    private int Port;             // destination port
    private int senderId;

    /**
     * @param type           packet type ("DATA", "ACK", or "HANDSHAKE")
     * @param sequenceNumber sequence number (0 for HANDSHAKE)
     * @param content        payload (key for HANDSHAKE)
     * @param Address        destination IP address
     * @param Port           destination port
     */
    public Packet(int senderId, String type, int sequenceNumber, Message content, InetAddress Address, int Port) {
        this.senderId = senderId;
        this.type = type;
        this.sequenceNumber = sequenceNumber;
        this.content = content;
        this.Address = Address;
        this.Port = Port;
    }

    /** Returns the payload content. */
    public Message getMessage() {
        return content;
    }

    /** Returns the Base64-encoded MAC string. */
    public String getAuthorship() {
        return this.mac;
    }

    /** Returns the sequence number. */
    public int getSequenceNumber() {
        return this.sequenceNumber;
    }

    /** Returns the packet type. */
    public String getType() {
        return this.type;
    }

    /** Returns the destination IP address. */
    public InetAddress getAddress() {
        return this.Address;
    }

    /** Returns the destination port. */
    public int getPort() {
        return this.Port;
    }

    /** Get the sender's node ID. */
    public int getSenderId() {
        return this.senderId;
    }

    /** Sets the destination IP address. */
    public void setAddress(InetAddress address) {
        this.Address = address;
    }
    /** Sets the destination port. */
    public void setPort(int port) {
        this.Port = port;
    }

    /** Sets the MAC string directly */
    void setMac(String mac) {
        this.mac = mac;
    }

    /**
     * Signs this DATA/ACK packet by computing an HMAC over type, sequence number, content and senderId.
     */
    public void sign(String secretKey) throws Exception {
        String dataToSign = this.type + "|" + this.sequenceNumber + "|" + this.content.formatMessage() + "|" + this.senderId;
        byte[] rawMac = Hasher.generateMAC(dataToSign.getBytes(), secretKey);
        this.mac = Base64.getEncoder().encodeToString(rawMac);
    }

    /**
     * Verifies this DATA/ACK packet's HMAC.
     */
    public boolean verify(String secretKey) {
        try {
            String dataToVerify = this.type + "|" + this.sequenceNumber + "|" + this.content.formatMessage() + "|" + this.senderId;
            return Hasher.verifyMAC(dataToVerify.getBytes(), Base64.getDecoder().decode(this.mac), secretKey);
        } catch (Exception e) {
            return false;
        }
    }

    /** Serializes this packet to a JSON string. */
    public String formatPacket(){
        return gson.toJson(this);
    }

    public static Packet fromJson(String json) {
        return gson.fromJson(json, Packet.class);
    }
}
