package depchain.client.protocol;

import depchain.common.network.Message;
import depchain.common.protocol.ClientRequest;
import depchain.common.protocol.ClientResponse;

import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for RequestTranslator.
 *
 * Verifies that transaction requests are correctly serialized into
 * ClientRequest JSON and that node responses can be correctly deserialized.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RequestTranslatorTest {

    // =========================================================================
    // Test 1 – createTransaction populates expected fields
    // =========================================================================

    /**
     * Verifies that all ClientRequest fields (clientId, requestId, to, value,
     * gasLimit, gasPrice, data) are correctly set by createTransaction.
     */
    @Test @Order(1)
    void createTransactionPopulatesFields() {
        ClientRequest req = RequestTranslator.createTransaction(
                4, 1, "0x01", 10L, 21000L, 2L, "0xdeadbeef");

        assertEquals(4, req.getClientId(), "clientId must match");
        assertEquals(1, req.getRequestId(), "requestId must match");
        assertEquals("0x01", req.getTo(), "to must match");
        assertEquals(10L, req.getValue(), "value must match");
        assertEquals(21000L, req.getGasLimit(), "gasLimit must match");
        assertEquals(2L, req.getGasPrice(), "gasPrice must match");
        assertEquals("0xdeadbeef", req.getData(), "data must match");
    }

    // =========================================================================
    // Test 2 – createTransaction content is parseable ClientRequest JSON
    // =========================================================================

    /**
     * The JSON produced by toJson() must round-trip back to a ClientRequest
     * with identical field values via fromJson().
     */
    @Test @Order(2)
    void createTransactionContentIsValidJson() {
        ClientRequest original = RequestTranslator.createTransaction(
                4, 1, "0x02", 0L, 50000L, 1L, "");
        ClientRequest req = ClientRequest.fromJson(original.toJson());

        assertEquals(4, req.getClientId(), "clientId must match");
        assertEquals(1, req.getRequestId(), "requestId must match");
        assertEquals("0x02", req.getTo(), "to must match");
        assertEquals(0L, req.getValue(), "value must match");
        assertEquals(50000L, req.getGasLimit(), "gasLimit must match");
        assertEquals(1L, req.getGasPrice(), "gasPrice must match");
        assertEquals("", req.getData(), "data must match");
    }

    // =========================================================================
    // Test 3 – parseResponse round-trips correctly
    // =========================================================================

    /**
     * A ClientResponse serialized to JSON and wrapped in a Message must be
     * correctly deserialized by parseResponse, preserving requestId, success
     * flag, result string, and nodeId.
     */
    @Test @Order(3)
    void parseResponseRoundTrip() {
        ClientResponse original = new ClientResponse(1, true, "OK", 2);
        Message msg = new Message(original.toJson(), "CLIENT_RESPONSE");

        ClientResponse parsed = RequestTranslator.parseResponse(msg);

        assertEquals(1, parsed.getRequestId(), "requestId must survive round-trip");
        assertTrue(parsed.isSuccess(),              "success flag must survive round-trip");
        assertEquals("OK", parsed.getResult(),      "result must survive round-trip");
        assertEquals(2,    parsed.getNodeId(),      "nodeId must survive round-trip");
    }

    // =========================================================================
    // Test 4 – Each call to createTransaction with different values
    //          produces distinct non-equal JSON
    // =========================================================================

    /**
     * Two requests built with different parameters must serialize to
     * different JSON strings, confirming field independence.
     */
    @Test @Order(4)
    void differentValuesProduceDifferentMessages() {
        ClientRequest r1 = RequestTranslator.createTransaction(
            4, 1, "0x01", 1L, 21000L, 1L, "0xaa");
        ClientRequest r2 = RequestTranslator.createTransaction(
            4, 2, "0x02", 2L, 21000L, 1L, "0xbb");

        assertNotEquals(r1.toJson(), r2.toJson(),
            "Requests with different fields must have different content");
    }

    // =========================================================================
    // Test 5 – parseResponse handles a failed response
    // =========================================================================

    /**
     * A ClientResponse with success=false and an error message must be
     * correctly deserialized, preserving the failure flag and error text.
     */
    @Test @Order(5)
    void parseResponseHandlesFailure() {
        ClientResponse original = new ClientResponse(2, false, "APPEND FAILED: disk full", 3);
        Message msg = new Message(original.toJson(), "CLIENT_RESPONSE");

        ClientResponse parsed = RequestTranslator.parseResponse(msg);

        assertFalse(parsed.isSuccess(),                          "failure flag must be preserved");
        assertTrue(parsed.getResult().contains("APPEND FAILED"), "error message must be preserved");
        assertEquals(3, parsed.getNodeId(),                      "nodeId must be preserved");
    }
}
