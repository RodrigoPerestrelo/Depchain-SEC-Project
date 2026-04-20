
package depchain.client.protocol;

import depchain.common.network.Message;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;

/**
 * Test utility for constructing and parsing client protocol messages.
 * Intended only for unit and integration tests — production code should
 * not construct ClientRequest objects directly.
 */
public class RequestTranslator {

    /**
     * Translates raw inputs into an EVM-compatible transaction request.
     */
    public static ClientRequest createTransaction(int clientId, int requestId, String to, long value, long gasLimit, long gasPrice, String data) {
        long timestamp = System.currentTimeMillis();
        return new ClientRequest(clientId, requestId, to, value, gasLimit, gasPrice, data, timestamp);
    }

    public static ClientResponse parseResponse(Message msg) {
        return ClientResponse.fromJson(msg.getContent());
    }
}
