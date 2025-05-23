import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Receiver {
    public static void main(String[] args) throws Exception {

        // Load the receiver's private RSA key
        PrivateKey receiverPrivateKey = loadPrivateKey("keys/party2_private.key");

        try (DataInputStream in = new DataInputStream(new FileInputStream("Transmitted_Data.dat"))) {
            // Read the file data and store into variables
            int ivLen = in.readInt(); 
            byte[] iv = in.readNBytes(ivLen);

            int aesKeyLen = in.readInt(); 
            byte[] encryptedAESKey = in.readNBytes(aesKeyLen);

            int messageLen = in.readInt(); 
            byte[] encryptedMessage = in.readNBytes(messageLen);

            int macLen = in.readInt(); 
            byte[] receivedMac = in.readNBytes(macLen);

            // Decrypt the AES key with the receiver's private RSA key
            SecretKey decryptKey = decryptAESKey(encryptedAESKey, receiverPrivateKey);

            // Verify the MAC
            verifyMAC(encryptedMessage, encryptedAESKey, receivedMac, decryptKey.getEncoded());

            // Decrypt the message with the decrypted AES key and IV, then print the message
            decryptMessage(encryptedMessage, decryptKey, iv);
        }
    }

    // Loads a private key from a file path (https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html)
    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        // Read the key bytes from the file and create a private key spec
        byte[] encodedKey = Files.readAllBytes(new File(filename).toPath());

        // Uses PKCS8EncodedKeySpec because private key format is different from public key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);

        // Generate the private key from the keySpec and return it
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    // Generate a MAC with the info in the data and compare it with the received MAC (https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html)
    private static void verifyMAC(byte[] message, byte[] encryptAESKey, byte[] receivedMac, byte[] MACkey) throws Exception {
        SecretKey macKey = new SecretKeySpec(MACkey, "HmacSHA256");
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
