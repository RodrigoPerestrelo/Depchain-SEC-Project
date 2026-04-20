package depchain.common.crypto;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for HMAC-SHA256 based message authentication.
 */
public class Hasher {

    private static final String HMAC_ALGO = "HmacSHA256";
    public static final int MAC_LENGTH = 32;

    /**
     * Generates an HMAC-SHA256 tag for the given payload.
     *
     * @param payload   the data to authenticate
     * @param secretKey the shared secret key
     * @return the computed MAC bytes
     * @throws Exception if the HMAC algorithm or key is invalid
     */
    public static byte[] generateMAC(byte[] payload, String secretKey) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), HMAC_ALGO);
        mac.init(keySpec);
        return mac.doFinal(payload);
    }

    /**
     * Verifies an HMAC-SHA256 tag against the expected value for the given payload.
     *
     * @param payload     the original data
     * @param receivedMac the MAC to verify
     * @param secretKey   the shared secret key
     * @return true if the MAC is valid, false otherwise
     */
    public static boolean verifyMAC(byte[] payload, byte[] receivedMac, String secretKey) {
        try {
            byte[] expectedMac = generateMAC(payload, secretKey);
            return MessageDigest.isEqual(expectedMac, receivedMac);
        } catch (Exception e) {
            return false;
        }
    }
}