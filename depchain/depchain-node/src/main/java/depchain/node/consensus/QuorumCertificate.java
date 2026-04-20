package depchain.node.consensus;

import threshsig.SigShare;

/**
 * Quorum Certificate (QC) — Section 4 of the HotStuff paper.
 *
 * A QC proves that at least n − f honest replicas voted for node
 * in a given phase and view.  The sigs array holds the individual
 * SigShares collected by the leader; any node can re-verify the QC by calling
 * ThresholdSignatureService.tverify(sigs, type, viewNumber, node).
 */
public class QuorumCertificate {

    private final String     type;
    private final int        viewNumber;
    private final Block      node;
    private final SigShare[] sigs;

    /**
     * @param type       phase (PREPARE / PRE-COMMIT / COMMIT / DECIDE)
     * @param viewNumber view in which this QC was formed
     * @param node       block this QC certifies
     * @param sigs       the n − f partial signature shares
     */
    public QuorumCertificate(String type, int viewNumber, Block node, SigShare[] sigs) {
        this.type       = type;
        this.viewNumber = viewNumber;
        this.node       = node;
        this.sigs       = sigs != null ? sigs : new SigShare[0];
    }

    public String     getType()       { return type; }
    public int        getViewNumber() { return viewNumber; }
    public Block      getNode()       { return node; }
    /** Returns the partial-signature shares that constitute this quorum. */
    public SigShare[] getSigs()       { return sigs; }

    /** True iff this QC has the given phase type and view number. */
    public boolean matches(String type, int viewNumber) {
        return this.type.equals(type) && this.viewNumber == viewNumber;
    }
}