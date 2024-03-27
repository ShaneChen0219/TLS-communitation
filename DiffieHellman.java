import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {

    private static final BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    public static byte[] generateNonce(){
        SecureRandom random = new SecureRandom();
        byte[] sectionKey = new byte[32];
        random.nextBytes(sectionKey);
        return sectionKey;
    }

    public static BigInteger[] generateKeyPair() {
        // Generate a random secret key and its corresponding public key
        SecureRandom random = new SecureRandom();
        BigInteger privateKey = new BigInteger(N.bitLength(), random);
        privateKey = privateKey.mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE); // Ensure privateKey is in the range [1, N-1]
        BigInteger publicKey = g.modPow(privateKey, N);
        return new BigInteger[]{privateKey, publicKey};
    }

    public static byte[] generateShareKey(BigInteger otherSidePublicKey, BigInteger MyOwnPrivateKey){
        return otherSidePublicKey.modPow(MyOwnPrivateKey,N).toByteArray();
    }

}
