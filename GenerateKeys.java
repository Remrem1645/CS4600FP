import java.io.*;
import java.security.*;

public class GenerateKeys {

    // RUN THIS FIRST TO GET THE KEYS
    public static void main(String[] args) throws Exception {
        generateKeyPair("party1");
        generateKeyPair("party2");
    }

    // Generates a public/private (https://www.baeldung.com/java-rsa)
    public static void generateKeyPair(String name) throws Exception {

        // Set up the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

        // Initialize the key pair generator with a key size of 2048 bits
        keyGen.initialize(2048);

        // Generate the key pair
        KeyPair keyPair = keyGen.generateKeyPair();

        // Creates the files to store the keys in the "keys" directory
        try (FileOutputStream publicFile = new FileOutputStream("keys/" + name + "_public.key");
                FileOutputStream privateFile = new FileOutputStream("keys/" + name + "_private.key")) {
            publicFile.write(keyPair.getPublic().getEncoded());
            privateFile.write(keyPair.getPrivate().getEncoded());
        }
    }
}