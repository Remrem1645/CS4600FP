import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.spec.*;

public class Receiver {
    public static void main(String[] args) throws Exception {

        // Load the receiver's private RSA key
        PrivateKey receiverPrivateKey = loadPrivateKey("keys/party2_private.key");

        try (DataInputStream in = new DataInputStream(new FileInputStream("Transmitted_Data.dat"))) {
            int ivLen = in.readInt(); byte[] iv = in.readNBytes(ivLen);
            int aesKeyLen = in.readInt(); byte[] encryptedAesKey = in.readNBytes(aesKeyLen);
            int messageLen = in.readInt(); byte[] encryptedMessage = in.readNBytes(messageLen);
            int macLen = in.readInt(); byte[] receivedMac = in.readNBytes(macLen);

            // Verify the MAC
            verifyMAC(encryptedMessage, encryptedAesKey, receivedMac, "key");

            // Decrypt the AES key with the receiver's private RSA key
            SecretKey decryptKey = decryptAESKey(encryptedAesKey, receiverPrivateKey);

            // Decrypt the message with the decrypted AES key and IV, then print the message
            decryptMessage(encryptedMessage, decryptKey, iv);
        }
    }

    // Loads a private key from a file path (https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html)
    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        // Read the key bytes from the file and create a private key spec
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

        // Uses PKCS8EncodedKeySpec because private key format is different from public key
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        // Generate the private key from the spec and return it
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // Generate a MAC with the info in the data and compare it with the received MAC (https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html)
    private static void verifyMAC(byte[] message, byte[] encryptAESKey, byte[] receivedMac, String key) throws Exception {
        SecretKey macKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        mac.update(message);
        mac.update(encryptAESKey);
        
        byte[] calculatedMac = mac.doFinal();

        if (!MessageDigest.isEqual(calculatedMac, receivedMac)) {
            throw new Exception("MAC verification failed");
        }
    }

    // Decrypts the AES key with the receiver's private RSA key (https://www.baeldung.com/java-cipher-class#5-encryption-and-decryption)
    private static SecretKey decryptAESKey(byte[] encryptedAESKey, PrivateKey receiverPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        byte[] decryptedAESKey = cipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(decryptedAESKey, "AES");
    }

    // Decrypts the message with the decrypted AES key and IV (https://www.baeldung.com/java-cipher-class#5-encryption-and-decryption)
    private static void decryptMessage(byte[] encryptedMessage, SecretKey decryptKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, decryptKey, new IvParameterSpec(iv));
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        System.out.println( "Message Content: " +  new String(decryptedMessage));
    }
}
