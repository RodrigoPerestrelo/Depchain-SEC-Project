package depchain.common.protocol;

import com.google.gson.Gson;
import threshsig.SigShare;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * A transferable proof that consensus was reached on a block.
 *
 * <p>This is derived from the HotStuff commitQC: it contains
 * the signed message type, the view number, the committed block's hash,
 * and the k threshold signature shares that together prove
 * 2f+1 replicas voted COMMIT for that exact block.
 *
 * <p>The client verifies a CommitProof by recomputing
 * getSignedBytes() and calling
 * depchain.common.crypto.PKIProvider#verifyCommitProof(CommitProof).
 * A single valid proof from any replica is sufficient — the threshold
 * signature is unforgeable without controlling k replicas' key shares.
 */
public class CommitProof {

    private static final Gson gson = new Gson();

    private final String     type;        // always "COMMIT"
    private final int        viewNumber;
    private final String     blockHash;   // Block.computeHash() of the decided block
    private final SigShare[] sigs;        // k threshold signature shares

    public CommitProof(String type, int viewNumber, String blockHash, SigShare[] sigs) {
        this.type        = type;
        this.viewNumber  = viewNumber;
        this.blockHash   = blockHash;
        this.sigs        = sigs;
    }

    public String     getType()       { return type; }
    public int        getViewNumber() { return viewNumber; }
    public String     getBlockHash()  { return blockHash; }
    public SigShare[] getSigs()       { return sigs; }

    /**
     * Returns the SHA-1 digest of "type|viewNumber|blockHash",
     * which is the exact byte sequence that was threshold-signed during
     * the HotStuff COMMIT phase.
     */
    public byte[] getSignedBytes() throws Exception {
        String msg = type + "|" + viewNumber + "|" + blockHash;
        return MessageDigest.getInstance("SHA-1")
                            .digest(msg.getBytes(StandardCharsets.UTF_8));
    }

    public String toJson()                          { return gson.toJson(this); }
    public static CommitProof fromJson(String json) { return gson.fromJson(json, CommitProof.class); }
}
