package depchain.node.crypto;

import depchain.common.crypto.PKIProvider;
import depchain.node.consensus.Block;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import threshsig.SigShare;
import threshsig.ThresholdSigException;

/**
 * Provides threshold signature operations for HotStuff.
 *
 * tsign  – each replica signs a vote message with its KeyShare
 * tcombine – the leader collects k partial SigShares
 * verify  – any node can verify k collected shares against the GroupKey
 */
public class ThresholdSignatureService {

    private final PKIProvider pki;
    private final int myId;

    public ThresholdSignatureService(PKIProvider pki, int myId) {
        this.pki = pki;
        this.myId = myId;
    }

    /**
     * Produces a partial signature share over (type, viewNumber, block).
     *
     * @return a SigShare to be broadcast to other replicas
     */
    public SigShare tsign(String type, int viewNumber, Block block) throws Exception {
        byte[] digest = sha1(type + "|" + viewNumber + "|" + block.computeHash());
        return pki.threshSign(digest);
    }

    /**
     * Verifies that k collected shares are valid for the given message.
     *
     * @param shares     exactly k SigShares collected from different replicas
     * @param type       message type
     * @param viewNumber view number
     * @param block      the block being voted on
     * @return true if the combined threshold signature is valid
     */
    public boolean tverify(SigShare[] shares, String type, int viewNumber, Block block)
            throws ThresholdSigException, Exception {
        byte[] digest = sha1(type + "|" + viewNumber + "|" + block.computeHash());
        return pki.threshVerify(digest, shares);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** SHA-1 digest of s (same as ThreshTest). */
    private static byte[] sha1(String s) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(
                s.getBytes(StandardCharsets.UTF_8));
    }
}
