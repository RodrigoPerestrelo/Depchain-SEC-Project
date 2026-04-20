package depchain.node.consensus;

import com.google.gson.Gson;

/**
 * Response message containing recovered blocks from a replica.
 * Sent in response to a BlockFetchRequest.
 *
 * Contains the blocks traversing backwards towards genesis.
 */
public class BlockFetchResponse {
    private static final Gson gson = new Gson();

    private final String requestId;    // Matches the requesting BlockFetchRequest.requestId
    private final int senderId;        // Which node is sending this response
    private final Block[] blocks;      // Array of blocks in order (oldest first)
    private final String status;       // "OK" or "NOTFOUND"

    public BlockFetchResponse(String requestId, int senderId, Block[] blocks, String status) {
        this.requestId = requestId;
        this.senderId = senderId;
        this.blocks = blocks != null ? blocks : new Block[0];
        this.status = status;
    }

    public String getRequestId() {
        return requestId;
    }

    public int getSenderId() {
        return senderId;
    }

    public Block[] getBlocks() {
        return blocks;
    }

    public String getStatus() {
        return status;
    }

    public String formatMessage() {
        return gson.toJson(this);
    }

    public static BlockFetchResponse fromJson(String json) {
        return gson.fromJson(json, BlockFetchResponse.class);
    }
}
