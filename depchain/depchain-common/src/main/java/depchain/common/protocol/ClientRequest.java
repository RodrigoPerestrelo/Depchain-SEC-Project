package depchain.common.protocol;

import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;

public class ClientRequest {
    private static final Gson gson = new Gson();

    private int clientId;
    private int requestId;

    // EVM transaction fields
    private String to;
    private long value;
    private long gasLimit;
    private long gasPrice;
    private String data;
    
    /** Base64-encoded ECDSA signature over the canonical bytes. Null if unsigned. */
    private long timestamp;
    private String signature;

    public ClientRequest() {}

    public ClientRequest(int clientId, int requestId, String to, long value,
                         long gasLimit, long gasPrice, String data, long timestamp) {
        this.clientId  = clientId;
        this.requestId = requestId;
        this.to = to;
        this.value = value;
        this.gasLimit = gasLimit;
        this.gasPrice = gasPrice;
        this.data = data;
        this.timestamp = timestamp;
    }

    public int getClientId()     { return clientId; }
    public int getRequestId() { return requestId; }
    public String getTo() { return to; }
    public long getValue()     { return value; }
    public long getGasLimit()  { return gasLimit; }
    public long getGasPrice()  { return gasPrice; }
    public String getData()    { return data; }
    public long getTimestamp()  { return timestamp; }
    public String getSignature() { return signature; }

    public void setSignature(String sig) {
        this.signature = sig;
    }

    // Generate byte array for ECDSA signing
    public byte[] getSigningData() {
        String rawData = clientId + "|" + requestId + "|" + 
                         (to != null ? to : "") + "|" + 
                         value + "|" + gasLimit + "|" + gasPrice + "|" + 
                         (data != null ? data : "") + "|" + timestamp;
        return rawData.getBytes(StandardCharsets.UTF_8);
    }

    public String toJson()                          { return gson.toJson(this); }
    public static ClientRequest fromJson(String j)  { return gson.fromJson(j, ClientRequest.class); }
}
