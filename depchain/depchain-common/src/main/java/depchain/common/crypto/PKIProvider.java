package depchain.common.crypto;

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import threshsig.Dealer;
import threshsig.GroupKey;
import threshsig.KeyShare;
import threshsig.SigShare;
import threshsig.ThresholdSigException;

/**
 * Manages ECDSA key pairs for replica authentication and threshold
 * (RSA-based) key material for collective signing.
 *
 * ECDSA keys are stored as Base64 files: node{id}.pub / node{id}.priv.
 * Threshold keys: groupkey.properties (shared) + node{id}.keyshare (per-node).
 * All key files must live in the same keysOutputDir.
 */
public class PKIProvider {

    private static final String ALGORITHM = "EC";
    private static final String EC_CURVE  = "secp256r1";

    // ECDSA keys
    private final Map<Integer, PublicKey> publicKeys;
    private final PrivateKey myPrivateKey;

    // Threshold-signature keys (null when not loaded from disk)
    private final GroupKey  groupKey;
    private final KeyShare  myKeyShare;

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Loads this node's ECDSA private key, all entities' ECDSA public keys,
     * the shared GroupKey, and this node's secret KeyShare from
     * keysOutputDir.
     *
     * @param keysOutputDir     directory that contains all key files
     * @param myId              0-based identifier of this entity
     * @param totalEntities     total number of entities (nodes + clients)
     * @param loadThresholdKeys whether to load threshold keys (false for clients)
     */
    public PKIProvider(String keysOutputDir, int myId, int totalEntities,
                       boolean loadThresholdKeys) throws Exception {
        this.publicKeys = new HashMap<>();
        KeyFactory keyfactory = KeyFactory.getInstance(ALGORITHM);

        for (int i = 0; i < totalEntities; i++) {
            String pubBase64 = Files.readString(Paths.get(keysOutputDir, "node" + i + ".pub")).trim();
            byte[] pubBytes = Base64.getDecoder().decode(pubBase64);

            publicKeys.put(i, keyfactory.generatePublic(new X509EncodedKeySpec(pubBytes)));
        }

        String privBase64 = Files.readString(Paths.get(keysOutputDir, "node" + myId + ".priv")).trim();
        byte[] privBytes = Base64.getDecoder().decode(privBase64);

        this.myPrivateKey = keyfactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

        if (loadThresholdKeys) {
            Path dir = Paths.get(keysOutputDir);
            this.groupKey   = loadGroupKey(dir);
            // Try to load the per-node keyshare; entities that only verify
            // (e.g. clients) may not have a keyshare file on disk.
            KeyShare ks = null;
            try {
                ks = loadKeyShare(dir, myId);
            } catch (IOException ignored) {}
            this.myKeyShare = ks;
        } else {
            this.groupKey   = null;
            this.myKeyShare = null;
        }
    }

    /**
     * Convenience constructor for nodes that always load threshold keys.
     */
    public PKIProvider(String keysOutputDir, int myId, int totalNodes) throws Exception {
        this(keysOutputDir, myId, totalNodes, true);
    }

    /**
     * In-memory constructor for unit tests (ECDSA only; threshold methods
     * will throw IllegalStateException if called on this instance).
     */
    public PKIProvider(PrivateKey myPrivateKey, Map<Integer, PublicKey> publicKeys) {
        this.myPrivateKey = myPrivateKey;
        this.publicKeys   = new HashMap<>(publicKeys);
        this.groupKey     = null;
        this.myKeyShare   = null;
    }

    // -------------------------------------------------------------------------
    // ECDSA helpers
    // -------------------------------------------------------------------------

    public PublicKey getPublicKey(int replicaId) {
        return publicKeys.get(replicaId);
    }

    public PrivateKey getMyPrivateKey() {
        return myPrivateKey;
    }

    /**
     * Signs data with this node's static ECDSA private key.
     *
     * @param data bytes to sign
     * @return DER-encoded ECDSA signature
     */
    public byte[] sign(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(myPrivateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies an ECDSA signature using a peer's static public key.
     *
     * @param data      original data
     * @param signature DER-encoded signature to verify
     * @param peerId    node ID whose public key to use
     * @return true if the signature is valid
     */
    public boolean verify(byte[] data, byte[] signature, int peerId) {
        try {
            PublicKey pubKey = publicKeys.get(peerId);
            if (pubKey == null) return false;

            Signature sign = Signature.getInstance("SHA256withECDSA");
            sign.initVerify(pubKey);
            sign.update(data);
            return sign.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Threshold-signature helpers
    // -------------------------------------------------------------------------

    /**
     * Returns the shared GroupKey.
     *
     * @throws IllegalStateException if threshold keys were not loaded from disk
     */
    public GroupKey getGroupKey() {
        requireGroupKey();
        return groupKey;
    }

    /**
     * Creates a partial (threshold) signature share for data using
     * this node's secret KeyShare.
     *
     * @param data bytes to sign
     * @return a SigShare to be broadcast to other nodes
     * @throws IllegalStateException if threshold keys were not loaded from disk
     */
    public SigShare threshSign(byte[] data) {
        requireThresholdKeys();
        return myKeyShare.sign(data);
    }

    /**
     * Verifies k combined threshold signature shares against
     * data using the shared GroupKey.
     *
     * <p>The shares array must contain exactly k distinct
     * (non-null) SigShare objects collected from different nodes.
     *
     * @param data   originally signed bytes
     * @param shares array of exactly k valid SigShares
     * @return true if the combined signature is valid
     * @throws ThresholdSigException if fewer than k distinct shares are provided
     *                               or a share fails its individual verifier check
     * @throws IllegalStateException if threshold keys were not loaded from disk
     */
    public boolean threshVerify(byte[] data, SigShare[] shares) throws ThresholdSigException {
        requireGroupKey();
        return SigShare.verify(data, shares,
                groupKey.getK(), groupKey.getL(),
                groupKey.getModulus(), groupKey.getExponent());
    }

    /**
     * Verifies the threshold proof of consensus embedded in a
     * depchain.common.protocol.CommitProof.
     *
     * @param proof the commit proof to verify
     * @return true if the threshold signature is valid
     * @throws IllegalStateException if the GroupKey was not loaded
     */
    public boolean verifyCommitProof(depchain.common.protocol.CommitProof proof) throws Exception {
        return threshVerify(proof.getSignedBytes(), proof.getSigs());
    }

    // -------------------------------------------------------------------------
    // Deserialisation helpers (threshold keys)
    // -------------------------------------------------------------------------

    /**
     * Reads groupkey.properties from dir and reconstructs a
     * GroupKey.
     */
    private static GroupKey loadGroupKey(Path dir) throws IOException {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(dir.resolve("groupkey.properties"))) {
            p.load(in);
        }
        int k        = Integer.parseInt(p.getProperty("k"));
        int l        = Integer.parseInt(p.getProperty("l"));
        BigInteger e = new BigInteger(p.getProperty("e"), 16);
        BigInteger n = new BigInteger(p.getProperty("n"), 16);
        // keysize and group-verifier v are not needed after initial generation
        return new GroupKey(k, l, 0, null, e, n);
    }

    /**
     * Reads node{nodeId}.keyshare from dir and reconstructs
     * the KeyShare (including verifiers).
     */
    private static KeyShare loadKeyShare(Path dir, int nodeId) throws IOException {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(dir.resolve("node" + nodeId + ".keyshare"))) {
            p.load(in);
        }
        int        id            = Integer.parseInt(p.getProperty("id"));
        BigInteger secret        = new BigInteger(p.getProperty("secret"),        16);
        BigInteger n             = new BigInteger(p.getProperty("n"),             16);
        BigInteger delta         = new BigInteger(p.getProperty("delta"),         16);
        BigInteger verifier      = new BigInteger(p.getProperty("verifier"),      16);
        BigInteger groupVerifier = new BigInteger(p.getProperty("groupVerifier"), 16);

        KeyShare ks = new KeyShare(id, secret, n, delta);
        ks.setVerifiers(verifier, groupVerifier);
        return ks;
    }

    // -------------------------------------------------------------------------
    // ECDSA key generation (static utility)
    // -------------------------------------------------------------------------

    /**
     * Generates a GroupKey and l KeyShares for a (k,l) threshold
     * signature scheme and writes them to keysOutputDir.
     *
     * @param keysOutputDir  directory where the key files are written (created if absent)
     * @param k              signature threshold (minimum shares required)
     * @param l              total number of shares / nodes
     * @param keyBits        RSA modulus bit-length (e.g. 1024)
     * @throws Exception if key generation or I/O fails
     */
    public static void generateThresholdKeys(String keysOutputDir, int k, int l, int keyBits)
            throws Exception {
        Path dir = Paths.get(keysOutputDir);
        Files.createDirectories(dir);

        Dealer dealer = new Dealer(keyBits);
        dealer.generateKeys(k, l);

        GroupKey   gk     = dealer.getGroupKey();
        KeyShare[] shares = dealer.getShares();

        saveGroupKey(dir, gk);

        // KeyShare IDs are 1-based; node IDs are 0-based.
        for (int i = 0; i < l; i++) {
            saveKeyShare(dir, i, shares[i]);
        }
    }

    private static void saveGroupKey(Path dir, GroupKey gk) throws IOException {
        Properties p = new Properties();
        p.setProperty("k", Integer.toString(gk.getK()));
        p.setProperty("l", Integer.toString(gk.getL()));
        p.setProperty("e", gk.getExponent().toString(16));
        p.setProperty("n", gk.getModulus().toString(16));
        try (OutputStream out = Files.newOutputStream(dir.resolve("groupkey.properties"))) {
            p.store(out, "GroupKey - threshold signature scheme");
        }
    }

    private static void saveKeyShare(Path dir, int nodeId, KeyShare share) throws IOException {
        Properties p = new Properties();
        p.setProperty("id",            Integer.toString(share.getId()));
        p.setProperty("secret",        share.getSecret().toString(16));
        p.setProperty("n",             share.getN().toString(16));
        p.setProperty("delta",         share.getDelta().toString(16));
        p.setProperty("verifier",      share.getVerifier().toString(16));
        p.setProperty("groupVerifier", share.getGroupVerifier().toString(16));
        try (OutputStream out = Files.newOutputStream(dir.resolve("node" + nodeId + ".keyshare"))) {
            p.store(out, "KeyShare for node " + nodeId + " (KEEP SECRET)");
        }
    }

    /**
     * Generates n ECDSA key pairs and writes them to keysOutputDir.
     *
     * @param keysOutputDir output directory
     * @param n             number of key pairs to generate
     */
    public static void generateKeys(String keysOutputDir, int n) throws Exception {
        Path dir = Paths.get(keysOutputDir);
        Files.createDirectories(dir);

        KeyPairGenerator keypairgenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keypairgenerator.initialize(new ECGenParameterSpec(EC_CURVE));

        for (int i = 0; i < n; i++) {
            KeyPair keypair  = keypairgenerator.generateKeyPair();
            String pubBase64 = Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
            String privBase64= Base64.getEncoder().encodeToString(keypair.getPrivate().getEncoded());

            Files.writeString(dir.resolve("node" + i + ".pub"),  pubBase64);
            Files.writeString(dir.resolve("node" + i + ".priv"), privBase64);
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /** Requires the shared GroupKey (needed for both signing and verification). */
    private void requireGroupKey() {
        if (groupKey == null) {
            throw new IllegalStateException(
                    "GroupKey not loaded. Use PKIProvider(keysDir, id, n, true).");
        }
    }

    /** Requires full threshold key material: GroupKey AND per-node KeyShare. */
    private void requireThresholdKeys() {
        requireGroupKey();
        if (myKeyShare == null) {
            throw new IllegalStateException(
                    "KeyShare not loaded. This entity has no threshold signing key.");
        }
    }
}
