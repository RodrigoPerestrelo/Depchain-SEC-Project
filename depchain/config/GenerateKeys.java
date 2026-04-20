package depchain.config;

import depchain.common.crypto.PKIProvider;

/**
 * Generates threshold (GroupKey + KeyShares) and ECDSA key pairs,
 * writing all files to disk via PKIProvider.
 */
public class GenerateKeys {

    /** RSA modulus bit-length for the threshold group key. */
    private static final int KEY_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: GenerateKeys <keysOutputDir> <k> <l> [<numClients>]");
            System.out.println("  k = minimum shares needed for a valid threshold signature");
            System.out.println("  l = total number of nodes");
            System.out.println("  numClients = number of clients (optional, default 0)");
            return;
        }

        String keysOutputDir = args[0];
        int k = Integer.parseInt(args[1]);
        int l = Integer.parseInt(args[2]);
        int numClients = args.length >= 4 ? Integer.parseInt(args[3]) : 0;

        PKIProvider.generateKeys(keysOutputDir, l + numClients);
        System.out.println("ECDSA key pairs for " + (l + numClients) + " entities written to: " + keysOutputDir);

        PKIProvider.generateThresholdKeys(keysOutputDir, k, l, KEY_SIZE);
        System.out.println("Threshold key material written to: " + keysOutputDir);
    }
}
