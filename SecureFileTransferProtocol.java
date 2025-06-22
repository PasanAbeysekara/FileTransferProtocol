import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public class SecureFileTransferProtocol {

    public static void main(String[] args) throws Exception {
        // 1. Generate RSA key pairs for Alice and Bob
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair aliceKeyPair = keyGen.generateKeyPair();
        KeyPair bobKeyPair = keyGen.generateKeyPair();

        // 2. Alice creates and signs a nonce
        String nonce = "nonce123";
        byte[] signedNonce = signData(nonce.getBytes(StandardCharsets.UTF_8), aliceKeyPair.getPrivate());

        // Encrypt the Nonce before sending
        byte[] encryptedNonce = rsaEncrypt(nonce.getBytes(StandardCharsets.UTF_8), bobKeyPair.getPublic());

        // <<<<<<<<<<<<<<<<<<<<<<<TRANSMIT>>>>>>>>>>>>>>>>>>>>>>>>>
        // Bob decrypts the message
        byte[] decryptedNonce = rsaDecrypt(encryptedNonce, bobKeyPair.getPrivate());

        // 3. Bob verifies Alice’s signature
        boolean isAliceValid = verifySignature(decryptedNonce, signedNonce, aliceKeyPair.getPublic());
        System.out.println("Step 3 - Alice Signature Valid? " + isAliceValid);

        // 4. Bob generates AES session key and IV
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128); // AES-128
        SecretKey aesSessionKey = aesGen.generateKey();
        byte[] iv = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);

        // 5. Bob encrypts AES session key and IV with Alice’s public key
        byte[] encryptedKey = rsaEncrypt(aesSessionKey.getEncoded(), aliceKeyPair.getPublic());
        byte[] encryptedIv = rsaEncrypt(iv, aliceKeyPair.getPublic());

        // Bob signs
        byte[] signedKey = signData(aesSessionKey.getEncoded(), bobKeyPair.getPrivate());
        byte[] signedIv = signData(iv, bobKeyPair.getPrivate());

        // AES session key + IV and their signatures will be sent via the medium
        // <<<<<<<<<<<<<<<<<<<<<<<TRANSMIT>>>>>>>>>>>>>>>>>>>>>>>>>
        // 6. Alice decrypts AES key and IV
        byte[] decryptedKey = rsaDecrypt(encryptedKey, aliceKeyPair.getPrivate());
        byte[] decryptedIv = rsaDecrypt(encryptedIv, aliceKeyPair.getPrivate());

        boolean isKeyValid = verifySignature(decryptedKey, signedKey, bobKeyPair.getPublic());
        System.out.println("Is - Session Key Valid? " + isKeyValid);
        boolean isIvValid = verifySignature(decryptedIv, signedIv, bobKeyPair.getPublic());
        System.out.println("Is IV valid?: " + isIvValid);

        SecretKeySpec aesKeyFromAlice = new SecretKeySpec(decryptedKey, "AES");
        IvParameterSpec ivSpecFromAlice = new IvParameterSpec(decryptedIv);

        System.out.println("Step 6 - AES key exchange complete.");
        System.out.println("==========================================");
        System.out.println("FILE TRANSFER PHASE");
        System.out.println("==========================================");

        // 7. File Transfer Simulation
        // Create a sample file for Alice to send
        String testFileContent = "This is a confidential document from Alice to Bob.\n" +
                "It contains sensitive information that must be protected.\n" +
                "The content is encrypted using AES and verified with SHA-256 hash.";
        
        byte[] fileData = testFileContent.getBytes(StandardCharsets.UTF_8);
        System.out.println("Step 7 - Original file content created (" + fileData.length + " bytes)");

        // 8. Alice calculates file hash (SHA-256)
        byte[] fileHash = calculateSHA256Hash(fileData);
        System.out.println("Step 8 - File hash calculated: " + bytesToHex(fileHash));

        // 9. Alice encrypts file using AES session key + IV
        byte[] encryptedFile = aesEncrypt(fileData, aesKeyFromAlice, ivSpecFromAlice);
        System.out.println("Step 9 - File encrypted with AES");

        // 10. Alice signs the file hash with her private key
        byte[] signedFileHash = signData(fileHash, aliceKeyPair.getPrivate());
        System.out.println("Step 10 - File hash signed by Alice");

        // 11. Create timestamp for the transfer
        long timestamp = System.currentTimeMillis();
        byte[] timestampBytes = String.valueOf(timestamp).getBytes(StandardCharsets.UTF_8);
        byte[] signedTimestamp = signData(timestampBytes, aliceKeyPair.getPrivate());

        System.out.println("========== TRANSMITTING FILE ==========");
        System.out.println("Sending: Encrypted file + File hash signature + Timestamp + Timestamp signature");

        // <<<<<<<<<<<<<<<<<<<<<<<TRANSMIT>>>>>>>>>>>>>>>>>>>>>>>>>
        // Encrypted file, signed hash, timestamp, and signed timestamp are transmitted

        // 12. Bob receives and verifies Alice's signature on the file hash
        boolean isFileHashSignatureValid = verifySignature(fileHash, signedFileHash, aliceKeyPair.getPublic());
        System.out.println("Step 12 - Alice's file hash signature valid? " + isFileHashSignatureValid);

        // 13. Bob verifies timestamp signature
        boolean isTimestampValid = verifySignature(timestampBytes, signedTimestamp, aliceKeyPair.getPublic());
        System.out.println("Step 13 - Timestamp signature valid? " + isTimestampValid);

        // 14. Bob decrypts the file using AES session key + IV
        SecretKeySpec bobsAesKey = new SecretKeySpec(decryptedKey, "AES");
        IvParameterSpec bobsIvSpec = new IvParameterSpec(decryptedIv);
        byte[] decryptedFileData = aesDecrypt(encryptedFile, bobsAesKey, bobsIvSpec);
        System.out.println("Step 14 - File decrypted by Bob");

        // 15. Bob calculates hash of the decrypted file
        byte[] bobCalculatedHash = calculateSHA256Hash(decryptedFileData);
        System.out.println("Step 15 - Bob calculated file hash: " + bytesToHex(bobCalculatedHash));

        // 16. Bob compares the hashes
        boolean hashesMatch = Arrays.equals(fileHash, bobCalculatedHash);
        System.out.println("Step 16 - File integrity verified? " + hashesMatch);

        // Display the final decrypted content
        String decryptedContent = new String(decryptedFileData, StandardCharsets.UTF_8);
        System.out.println("==========================================");
        System.out.println("DECRYPTED FILE CONTENT:");
        System.out.println("==========================================");
        System.out.println(decryptedContent);
        System.out.println("==========================================");
        System.out.println("\nSecure file transfer completed successfully!");
    }

    public static byte[] calculateSHA256Hash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    public static byte[] aesEncrypt(byte[] data, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public static byte[] aesDecrypt(byte[] encryptedData, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    public static byte[] rsaEncrypt(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] rsaDecrypt(byte[] encrypted, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encrypted);
    }
}
