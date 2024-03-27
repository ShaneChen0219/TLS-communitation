import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TLSClient {
    private static final String CA_CERTIFICATE_FILE = "./CAcertificate.pem";
    private static final String SERVER_CERTIFICATE_FILE = "./CASignedServerCertificate.pem";
    private static final String SERVER_PRIVATE_KEY_FILE = "./serverPrivateKey.der";
    private static final String CLIENT_PRIVATE_KEY_FILE = "./clientPrivateKey.der";

    private static final String CLIENT_CERTIFICATE_FILE = "./CASignedClientCertificate.pem";
    private static final int PORT = 12345;
    public static void main(String[] args) throws Exception {

        FileInputStream CACertificateFiles = new FileInputStream(CA_CERTIFICATE_FILE);
        CertificateFactory CAcf = CertificateFactory.getInstance("X.509");
        Certificate CACertificate =CAcf.generateCertificate(CACertificateFiles);
        CACertificateFiles.close();

        FileInputStream clientCertificateFiles = new FileInputStream(CLIENT_CERTIFICATE_FILE);
        CertificateFactory clientPrivateKeyCF = CertificateFactory.getInstance("X.509");
        Certificate clientCertificate = clientPrivateKeyCF.generateCertificate(clientCertificateFiles);
        clientCertificateFiles.close();

        FileInputStream clientPrivateKeyFile = new FileInputStream(CLIENT_PRIVATE_KEY_FILE);
        byte[] keyBytesClient = new byte[clientPrivateKeyFile.available()];
        clientPrivateKeyFile.read(keyBytesClient);
        clientPrivateKeyFile.close();
        KeyFactory clientKF = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec specClient = new PKCS8EncodedKeySpec(keyBytesClient);
        PrivateKey clientPrivateKey = clientKF.generatePrivate(specClient);


        Socket socket = new Socket("localhost", ShareMethodAndInfo.PORT);
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

        //client creates and sends a nonce
        byte[] nonce = DiffieHellman.generateNonce();
//        for (byte i :nonce){
//            System.out.println(i);
//        }
        out.writeObject(nonce);
        out.flush();

        //receive server certificate, serverDHPub and a signed Diffie-Hellman public key as Enc(serverRSAPriv, serveDHPub)
        Certificate serverCertificate = (Certificate)in.readObject();
        BigInteger serverDHPubKey = (BigInteger) in.readObject();
        byte[] signedServerDHPub = (byte[]) in.readObject();
        serverCertificate.verify(CACertificate.getPublicKey());
        System.out.println("Certificate verified successfully.");

        //send client certificate, clientDHPub, and signed Diffie-Hellman public key
        out.writeObject(clientCertificate);
        //Client DH public key
        BigInteger[] clientDHKeyPair = DiffieHellman.generateKeyPair();
        BigInteger clientDHPri = clientDHKeyPair[0];
        BigInteger clientDHPub = clientDHKeyPair[1];
        out.writeObject(clientDHPub);

        // signed client public key
        Cipher cDPub = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cDPub.init(Cipher.ENCRYPT_MODE,clientPrivateKey);
        byte[] DHPubClient = cDPub.doFinal(clientDHPub.toByteArray());
        out.writeObject(DHPubClient);
        out.flush();

        //generate the share secrete
        byte[] sharedSecrete = DiffieHellman.generateShareKey(serverDHPubKey,clientDHPri);
//        for (byte i : sharedSecrete){
//            System.out.println(i);
//        }

        //session keys using HKDF
        ShareMethodAndInfo.makeSecretKeys(nonce,sharedSecrete);
        byte[] expectHMAC = ShareMethodAndInfo.calculateHmac(ShareMethodAndInfo.SERVER_MAC,nonce,serverCertificate.getEncoded(),serverDHPubKey.toByteArray(),signedServerDHPub,clientCertificate.getEncoded(),clientDHPub.toByteArray(),DHPubClient);
        byte[] receivedHMAC = (byte[]) in.readObject();
        if (!Arrays.equals(expectHMAC,receivedHMAC)){
            throw new Exception("HMAC verification failed");
        }

        byte[]hmac = ShareMethodAndInfo.calculateHmac(ShareMethodAndInfo.CLIENT_MAC,nonce,serverDHPubKey.toByteArray(),DHPubClient,clientCertificate.getEncoded(),clientDHPub.toByteArray(),DHPubClient,nonce,serverCertificate.getEncoded(),serverDHPubKey.toByteArray(),signedServerDHPub,clientCertificate.getEncoded(),clientDHPub.toByteArray(),DHPubClient);
        System.out.println(hmac.length);
        out.writeObject(hmac);
        out.flush();
        System.out.println("Client handshake completed");

        String hello = "Hello, World";
        System.out.println(hello);
        byte[] message = hello.getBytes();

        byte[] hmacMessage = ShareMethodAndInfo.calculateHmac(ShareMethodAndInfo.CLIENT_MAC,message);
        byte[] combinedMessage = new byte[message.length+hmacMessage.length];
        System.arraycopy(message, 0, combinedMessage, 0, message.length);
        System.arraycopy(hmacMessage, 0, combinedMessage, message.length, hmacMessage.length);
        byte[] sendMessage = ShareMethodAndInfo.encryptMessage(ShareMethodAndInfo.CLIENT_ENCRYPT,combinedMessage);
        out.writeObject(sendMessage);

    }
}
