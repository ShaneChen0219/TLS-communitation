import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class ShareMethodAndInfo {
    public static final String CA_CERTIFICATE_FILE = "./CAcertificate.pem";
    public static final String SERVER_CERTIFICATE_FILE = "./CASignedServerCertificate.pem";
    public static final String SERVER_PRIVATE_KEY_FILE = "./serverPrivateKey.der";
    public static final String CLIENT_PRIVATE_KEY_FILE = "./clientPrivateKey.der";

    public static final String CLIENT_CERTIFICATE_FILE = "./CASignedClientCertificate.pem";
    public static final int PORT = 12345;

    public static byte[] SERVER_ENCRYPT;
    public static byte[] SERVER_MAC;
    public static byte[] SERVER_IV;
    public static byte[] CLIENT_ENCRYPT;
    public static byte[] CLIENT_MAC;
    public static byte[] CLIENT_IV;

    public static byte[] encryptMessage(byte[] key,byte[] message) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey secretKey = new SecretKeySpec(key,"AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message);
    }

    public static byte[] decryptMessage(byte[] key ,byte[]message) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey secretKey = new SecretKeySpec(key,"AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(message);
    }

    public static byte[] hkdfExpand(byte[] input, String tag) throws Exception{
        Mac HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec spec = new SecretKeySpec(input, "RawBytes");
        HMAC.init(spec);
        HMAC.update(tag.getBytes());
        HMAC.update((byte)0x01);
        return Arrays.copyOf(HMAC.doFinal(), 16);
    }
    public static void makeSecretKeys(byte[] clientNonce, byte[]sharedSecretFromDiffieHellman) throws Exception{
        Mac HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec spec = new SecretKeySpec(clientNonce, "HmacSHA256");
        HMAC.init(spec);
        HMAC.update(sharedSecretFromDiffieHellman);
        byte[] prk = HMAC.doFinal();
        SERVER_ENCRYPT = ShareMethodAndInfo.hkdfExpand(prk, "server encrypt");
        CLIENT_ENCRYPT= hkdfExpand(SERVER_ENCRYPT, "client encrypt");
        SERVER_MAC = hkdfExpand(CLIENT_ENCRYPT, "server MAC");
        CLIENT_MAC = hkdfExpand(SERVER_MAC, "client MAC");
        SERVER_IV = hkdfExpand(CLIENT_MAC, "server IV");
        CLIENT_IV = hkdfExpand(SERVER_IV, "client IV");
    }

    public static byte[] calculateHmac(byte[] key, byte[]... messages) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKeySpec);
        for (byte[] message : messages) {
            mac.update(message);
        }
        return mac.doFinal();
    }
}
