import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TLSServer {

    private static final int PORT = 12345;

    public static void main(String[] args) throws Exception {

        FileInputStream CACertificateFiles = new FileInputStream(ShareMethodAndInfo.CA_CERTIFICATE_FILE);
        CertificateFactory CAcf = CertificateFactory.getInstance("X.509");
        Certificate CACertificate =CAcf.generateCertificate(CACertificateFiles);
        CACertificateFiles.close();

        FileInputStream serverCertificateFiles = new FileInputStream(ShareMethodAndInfo.SERVER_CERTIFICATE_FILE);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate serverCertificate = cf.generateCertificate(serverCertificateFiles);
        serverCertificateFiles.close();

        FileInputStream serverPrivateKeyFile = new FileInputStream(ShareMethodAndInfo.SERVER_PRIVATE_KEY_FILE);
        byte[] keyBytes = new byte[serverPrivateKeyFile.available()];
        serverPrivateKeyFile.read(keyBytes);
        serverPrivateKeyFile.close();
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey serverPrivateKey = kf.generatePrivate(spec);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "RSA");


        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server started, wait for client");
        Socket client = serverSocket.accept();
        System.out.println("Connected");

        //create input and output stream
        ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(client.getInputStream());

        // handshake
        // receive nonce
        byte[] nonce = (byte[]) in.readObject();
//        for (byte i :nonce){
//            System.out.println(i);
//        }

        //server sends the server certificate, serverDHPub and a signed Diffie-Hellman public key as Enc(serverRSAPriv, serveDHPub)
        // server certificate is the RSA certificate=> serverCertificate
        out.writeObject(serverCertificate);
        // Generate server's Diffie-Hellman key pair
        BigInteger[] serverDHKeyPair = DiffieHellman.generateKeyPair();
        BigInteger serverDHPri = serverDHKeyPair[0];
        BigInteger serverDHPub = serverDHKeyPair[1];
        out.writeObject(serverDHPub);

        //sign serverDHPub
        Cipher sDPub = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        sDPub.init(Cipher.ENCRYPT_MODE,serverPrivateKey);
        byte[] DHPubServer = sDPub.doFinal(serverDHPub.toByteArray());
        out.writeObject(DHPubServer);
        out.flush();

        //server receives client certification clientDHPub and a signed+Encrypt DH public key
        Certificate clientCertificate = (Certificate) in.readObject();
        BigInteger clientDHPubKey = (BigInteger) in.readObject();
        byte[] signedClientDHPub =(byte[]) in.readObject();
        clientCertificate.verify(CACertificate.getPublicKey());
        System.out.println("Certificate verified successfully.");

        //generate the shared secrete
        byte[] sharedSecrete = DiffieHellman.generateShareKey(clientDHPubKey,serverDHPri);
//        for (byte i : sharedSecrete){
//            System.out.println(i);
//        }

        //session keys using HKDF
        ShareMethodAndInfo.makeSecretKeys(nonce,sharedSecrete);
        //send HMAC of handshake history
        byte[] hmac = ShareMethodAndInfo.calculateHmac(ShareMethodAndInfo.SERVER_MAC,nonce,serverCertificate.getEncoded(),serverDHPub.toByteArray(),DHPubServer,clientCertificate.getEncoded(),clientDHPubKey.toByteArray(),signedClientDHPub);
        out.writeObject(hmac);
        out.flush();
        //receive HMAC of handshake history
        byte[] receivedHmac = (byte[]) in.readObject();


        byte[]encryptedMessageBytes = (byte[])in.readObject();
        byte[] decryptedMessageBytes = ShareMethodAndInfo.decryptMessage(ShareMethodAndInfo.CLIENT_ENCRYPT,encryptedMessageBytes);

        byte[] receivedMessage = new byte[decryptedMessageBytes.length - 32];
        byte[] receivedHmac2 = new byte[32];
        System.arraycopy(decryptedMessageBytes, 0, receivedMessage, 0, receivedMessage.length);
        System.arraycopy(decryptedMessageBytes, receivedMessage.length, receivedHmac2, 0, 32);
        System.out.println(new String(receivedMessage,"UTF-8"));
    }
}
