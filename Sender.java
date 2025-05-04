import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Sender {
    public static void main(String[] args) throws Exception {
        
        // Load the receiver's public RSA key
        PublicKey receiverPublicKey = loadPublicKey("keys/party2_public.key");
        
        // Generate a AES key for the sender
        SecretKey senderSecretKey = generateAESKey();

        // Encrypt the AES key with the receiver's public RSA key
        EncryptedData encryptedData = encryptMessage("message.txt", senderSecretKey);
        
        // Encrypt the AES key with the receiver's public RSA key
        byte[] encryptedAESKey = encryptAESKey(senderSecretKey, receiverPublicKey);

        // Generate a MAC for the encrypted message and AES key, the MAC key is "key"
        byte[] mac = generateMAC(encryptedData.message, encryptedAESKey, "key");

        // Write the encrypted message, IV, encrypted AES key, and MAC to a file
        try (DataOutputStream out = new DataOutputStream(new FileOutputStream("Transmitted_Data.dat"))) {
            out.writeInt(encryptedData.iv.length);
            out.write(encryptedData.iv);

            out.writeInt(encryptedAESKey.length);
            out.write(encryptedAESKey);

            out.writeInt(encryptedData.message.length);
            out.write(encryptedData.message);

            out.writeInt(mac.length);
            out.write(mac);
        }
    }

    // Loads a public key from a file path (https://www.baeldung.com/java-rsa#storingKeysInFiles)
    public static PublicKey loadPublicKey(String filename) throws Exception {
        // Read the key bytes from the file and create a public key spec
        byte[] bytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

        // Generate the public key from the spec and return it
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }


    // Generates a random AES key (https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyGenerator.html)
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); 
        return keyGen.generateKey();
    }

    // Encrypts the message (https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
    public static EncryptedData encryptMessage(String filename, SecretKey secretKey) throws Exception {

        // Read the message from the file
        byte[] message = Files.readAllBytes(new File(filename).toPath());

        // Setup the cipher for AES encryption with a random IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        // Initialize the cipher with the secret key and IV, then encrypt the message
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

        // Encrypt the message and return the encrypted data along with the IV
        byte[] encryptedMessage = cipher.doFinal(message);
        return new EncryptedData(encryptedMessage, iv);
    }

    // Encrypts the AES key with the receiver's public RSA key (https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html)
    public static byte[] encryptAESKey(SecretKey secretKey, PublicKey publicKey) throws Exception {
        // Setup the cipher for RSA encryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt the AES key and return the encrypted key
        return cipher.doFinal(secretKey.getEncoded());
    }

    // Generate MAC(https://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html)
    public static byte[] generateMAC(byte[] message, byte[] encryptAESKey, String MACkey) throws Exception {
        // Generate a MAC key using HMAC-SHA256
        SecretKey key = new SecretKeySpec(MACkey.getBytes(), "HmacSHA256");
        // Create a MAC instance and initialize it with the key
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        // Update the MAC and return the result
        mac.update(message);
        mac.update(encryptAESKey);
        return mac.doFinal();
    }

    // Class to hold the encrypted message and IV
    static class EncryptedData {
        byte[] message;
        byte[] iv;

        EncryptedData(byte[] message, byte[] iv) {
            this.message = message;
            this.iv = iv;
        }
    }
}
