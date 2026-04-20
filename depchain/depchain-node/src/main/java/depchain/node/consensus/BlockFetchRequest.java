package depchain.node.consensus;

import com.google.gson.Gson;

/**
 * Request message for fetching missing blocks from other replicas.
 * Used when a node encounters a gap in the block chain during execution.
 *
 * The recovering node requests the missing parent and its missing ancestors.
 */
public class BlockFetchRequest {
    private static final Gson gson = new Gson();

    private final String requestId;      // Unique identifier for this recovery attempt
    private final String fromParentHash;  // Fetch blocks starting from the parent of this hash

    public BlockFetchRequest(String requestId, String fromParentHash) {
        this.requestId = requestId;
        this.fromParentHash = fromParentHash;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getFromParentHash() {
        return fromParentHash;
    }

    public String formatMessage() {
        return gson.toJson(this);
    }

    public static BlockFetchRequest fromJson(String json) {
        return gson.fromJson(json, BlockFetchRequest.class);
    }
}
