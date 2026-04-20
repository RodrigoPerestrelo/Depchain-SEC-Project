package depchain.common.protocol;

import com.google.gson.Gson;

public class ClientResponse {
    private static final Gson gson = new Gson();

    private int      requestId;
    private boolean     success;
    private String      result;
    private int         nodeId;
    /**
     * Proof of consensus: the commitQC wrapped as a transferable DTO.
     * A valid CommitProof is a stronger authentication guarantee than
     * a per-node ECDSA signature — the threshold signature proves that at least
     * 2f+1 replicas agreed on this block.
     */
    private CommitProof commitProof;

    public ClientResponse(int requestId, boolean success, String result, int nodeId) {
        this.requestId = requestId;
        this.success   = success;
        this.result    = result;
        this.nodeId    = nodeId;
    }

    public int      getRequestId()  { return requestId; }
    public boolean     isSuccess()     { return success; }
    public String      getResult()     { return result; }
    public int         getNodeId()     { return nodeId; }
    public CommitProof getCommitProof(){ return commitProof; }
    public void setCommitProof(CommitProof proof) { this.commitProof = proof; }

    public String toJson()                          { return gson.toJson(this); }
    public static ClientResponse fromJson(String j) { return gson.fromJson(j, ClientResponse.class); }
}

