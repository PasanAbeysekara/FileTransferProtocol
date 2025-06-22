import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Base64;

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

        // 3. Bob verifies Alice’s signature
        boolean isAliceValid = verifySignature(nonce.getBytes(StandardCharsets.UTF_8), signedNonce, aliceKeyPair.getPublic());
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

        // 6. Alice decrypts AES key and IV
        byte[] decryptedKey = rsaDecrypt(encryptedKey, aliceKeyPair.getPrivate());
        byte[] decryptedIv = rsaDecrypt(encryptedIv, aliceKeyPair.getPrivate());

        SecretKeySpec aesKeyFromAlice = new SecretKeySpec(decryptedKey, "AES");
        IvParameterSpec ivSpecFromAlice = new IvParameterSpec(decryptedIv);

        System.out.println("Step 6 - AES key exchange complete.");
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
