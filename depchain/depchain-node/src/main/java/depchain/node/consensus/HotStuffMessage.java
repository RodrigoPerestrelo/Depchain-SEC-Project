package depchain.node.consensus;

import depchain.common.network.Message;
import depchain.common.network.Packet;
import depchain.node.crypto.ThresholdSignatureService;
import threshsig.SigShare;

import com.google.gson.Gson;

/**
 * HotStuff protocol message as described in Section 4 of the paper.
 * 
 * Messages are exchanged between the leader and replicas in each phase:
 * - Leader sends: (type, viewNumber, node, justify)
 * - Replica responds: same message with a partial signature
 */
public class HotStuffMessage {
    private static final Gson gson = new Gson();

    private final String type;
    private final int viewNumber;
    private final Block node;
    private final QuorumCertificate justify;
    private SigShare partialSig;

    /**
     * Creates a new HotStuff message.
     * 
     * @param type       phase type (PREPARE, PRE-COMMIT, COMMIT, DECIDE)
     * @param viewNumber current view number
     * @param node       the block being proposed/voted on
     * @param justify    QC that justifies this proposal
     */
    public HotStuffMessage(String type, int viewNumber, Block node, QuorumCertificate justify) {
        this.type = type;
        this.viewNumber = viewNumber;
        this.node = node;
        this.justify = justify;
    }

    public void setPartialSig(SigShare partialSig) {
        this.partialSig = partialSig;
    }

    public String getType() {
        return type;
    }

    public int getViewNumber() {
        return viewNumber;
    }

    public Block getNode() {
        return node;
    }

    public QuorumCertificate getJustify() {
        return justify;
    }

    public SigShare getPartialSig() {
        return partialSig;
    }

    /** Serializes this message to a JSON string. */
    public String formatMessage(){
        return gson.toJson(this);
    }

    public static HotStuffMessage fromJson(String json) {
        return gson.fromJson(json, HotStuffMessage.class);
    }

    /**
     * Checks if this message matches the given type and view number.
     */
    public boolean matches(String type, int viewNumber) {
        return this.type.equals(type) && this.viewNumber == viewNumber;
    }
}