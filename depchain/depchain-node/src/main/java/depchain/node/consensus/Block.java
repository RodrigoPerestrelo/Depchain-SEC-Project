package depchain.node.consensus;

import depchain.common.protocol.ClientRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.util.Objects;

/**
 * Block structure for Basic HotStuff (Section 4, Figure 2).
 * Contains: parent hash, client request.
 *
 * A block represents a ClientRequest that wants to be applied to the blockchain.
 * The ClientRequest contains all necessary fields including the client's signature.
 *
 * Only parentHash and clientRequest are serialized to JSON — the parent
 * reference is transient to avoid recursive nesting in Gson.
 * After deserialization, call setParent() to restore the in-memory link.
 */
public class Block {

    /** Pre-computed hash of the parent block, or null for the genesis block. */
    private final String parentHash;

    /** The transactions that this block represents. Null for genesis block. */
    private final List<ClientRequest> transactions;

    /** Transient parent ref — not serialized by Gson. Null on deserialized blocks. */
    private transient Block parent;

    /** Genesis block constructor (⊥ in the paper). */
    public Block() {
        this.parentHash = null;
        this.transactions = new ArrayList<>();
        this.parent = null;
    }

    /** Regular block constructor for a batch of transactions. */
    public Block(Block parent, List<ClientRequest> transactions) {
        this.parent = parent;
        this.parentHash = (parent != null) ? parent.computeHash() : null;
        this.transactions = (transactions != null) ? new ArrayList<>(transactions) : new ArrayList<>();
    }

    public Block getParent() {
        return parent;
    }

    public String getParentHash() {
        return parentHash;
    }

    public List<ClientRequest> getTransactions() {
        return transactions;
    }

    /** Restores the parent link after JSON deserialization. */
    public void setParent(Block parent) {
        this.parent = parent;
    }

    /** SHA-256 hash of parentHash and all transaction payloads. */
    public String computeHash() {
        try {
            String ph = (parentHash != null) ? parentHash : "genesis";
            StringBuilder dataBuilder = new StringBuilder(ph);
            
            for (ClientRequest tx : transactions) {
                if (tx != null) {
                    dataBuilder.append("|").append(tx.toJson());
                }
            }
            
            byte[] hash = MessageDigest.getInstance("SHA-256")
                                       .digest(dataBuilder.toString().getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash block", e);
        }
    }

    /**
     * Tests whether this block is a descendant of ancestor.
     * Walks the in-memory parent chain when available; falls back to
     * checking the direct parent hash for deserialized blocks.
     */
    public boolean extends_(Block ancestor) {
        if (ancestor == null) return true;   // everything extends genesis

        // Walk the in-memory chain when available
        Block current = this;
        while (current != null) {
            if (current.hashEquals(ancestor)) return true;
            current = current.parent;
        }

        // Fallback for deserialised blocks: check direct-parent hash
        String ancestorHash = ancestor.computeHash();
        return ancestorHash.equals(this.parentHash);
    }
    
    /** Content-based equality using computeHash(). */
    public boolean hashEquals(Block other) {
        if (this == other)   return true;
        if (other == null)   return false;
        return computeHash().equals(other.computeHash());
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Block other)) return false;
        return hashEquals(other);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(computeHash());
    }
}
