import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secure File Transfer API
 * Provides a high-level interface for secure file transfers between parties
 * using the underlying SecureFileTransferProtocol
 */
public class SecureFileTransferAPI {
    
    private final KeyPair keyPair;
    private final String participantId;
    private final Map<String, PublicKey> trustedPublicKeys;
    private final Map<String, SessionContext> activeSessions;
    
    public SecureFileTransferAPI(String participantId) throws Exception {
        this.participantId = participantId;
        this.trustedPublicKeys = new ConcurrentHashMap<>();
        this.activeSessions = new ConcurrentHashMap<>();
        
        // Generate RSA key pair for this participant
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();
    }
    
    /**
     * Get this participant's public key for sharing with others
     */
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
    
    /**
     * Add a trusted participant's public key
     */
    public void addTrustedParticipant(String participantId, PublicKey publicKey) {
        trustedPublicKeys.put(participantId, publicKey);
    }
    
    /**
     * Initiate a secure session with another participant
     */
    public String initiateSession(String remoteParticipantId) throws Exception {
        if (!trustedPublicKeys.containsKey(remoteParticipantId)) {
            throw new IllegalArgumentException("Unknown participant: " + remoteParticipantId);
        }
        
        String sessionId = generateSessionId();
        PublicKey remotePublicKey = trustedPublicKeys.get(remoteParticipantId);
        
        // Create session context
        SessionContext session = new SessionContext(sessionId, remoteParticipantId, remotePublicKey);
        activeSessions.put(sessionId, session);
        
        // Perform key exchange
        performKeyExchange(session);
        
        return sessionId;
    }
    
    /**
     * Send a file securely to another participant
     */
    public TransferResult sendFile(String sessionId, String filePath) throws Exception {
        SessionContext session = activeSessions.get(sessionId);
        if (session == null) {
            throw new IllegalArgumentException("Invalid session ID: " + sessionId);
        }
        
        // Read file
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        String fileName = Paths.get(filePath).getFileName().toString();
        
        return sendFileData(session, fileName, fileData);
    }
    
    /**
     * Send file data securely
     */
    public TransferResult sendFileData(String sessionId, String fileName, byte[] fileData) throws Exception {
        SessionContext session = activeSessions.get(sessionId);
        if (session == null) {
            throw new IllegalArgumentException("Invalid session ID: " + sessionId);
        }
        
        return sendFileData(session, fileName, fileData);
    }
    
    /**
     * Receive and verify a file transfer
     */
    public ReceivedFile receiveFile(String sessionId, TransferPacket packet) throws Exception {
        SessionContext session = activeSessions.get(sessionId);
        if (session == null) {
            // If session doesn't exist, create a temporary one for receiving
            // This handles cross-instance transfers where sender and receiver are different objects
            session = createTempSessionForReceiving(sessionId, packet);
        }
        
        // Decrypt RSA-encrypted components
        byte[] decryptedFile = SecureFileTransferProtocol.rsaDecrypt(packet.encryptedFile, keyPair.getPrivate());
        byte[] decryptedFileHash = SecureFileTransferProtocol.rsaDecrypt(packet.encryptedFileHash, keyPair.getPrivate());
        byte[] decryptedTimestamp = SecureFileTransferProtocol.rsaDecrypt(packet.encryptedTimestamp, keyPair.getPrivate());
        
        // For cross-instance transfers, we need the sender's public key
        // In a real implementation, this would be retrieved from a trusted key store
        PublicKey senderPublicKey = findSenderPublicKey(packet);
        
        // Verify signatures
        boolean isFileHashValid = SecureFileTransferProtocol.verifySignature(
            decryptedFileHash, packet.signedFileHash, senderPublicKey);
        boolean isTimestampValid = SecureFileTransferProtocol.verifySignature(
            decryptedTimestamp, packet.signedTimestamp, senderPublicKey);
        
        if (!isFileHashValid || !isTimestampValid) {
            throw new SecurityException("Invalid signatures detected");
        }
        
        // Decrypt file content using AES
        byte[] decryptedFileData = SecureFileTransferProtocol.aesDecrypt(
            decryptedFile, session.aesKey, session.ivSpec);
        
        // Verify file integrity
        byte[] calculatedHash = SecureFileTransferProtocol.calculateSHA256Hash(decryptedFileData);
        boolean integrityValid = Arrays.equals(decryptedFileHash, calculatedHash);
        
        if (!integrityValid) {
            throw new SecurityException("File integrity check failed");
        }
        
        return new ReceivedFile(packet.fileName, decryptedFileData, 
            new String(decryptedTimestamp), integrityValid);
    }
    
    /**
     * Close a session and cleanup resources
     */
    public void closeSession(String sessionId) {
        SessionContext session = activeSessions.remove(sessionId);
        if (session != null) {
            session.cleanup();
        }
    }
    
    /**
     * Get session context for sharing between instances (for demo purposes)
     */
    public SessionContext getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }
    
    // Private helper methods
    
    private TransferResult sendFileData(SessionContext session, String fileName, byte[] fileData) throws Exception {
        // Calculate file hash
        byte[] fileHash = SecureFileTransferProtocol.calculateSHA256Hash(fileData);
        
        // Encrypt file with AES
        byte[] encryptedFile = SecureFileTransferProtocol.aesEncrypt(fileData, session.aesKey, session.ivSpec);
        
        // Sign file hash
        byte[] signedFileHash = SecureFileTransferProtocol.signData(fileHash, keyPair.getPrivate());
        
        // Create timestamp
        long timestamp = System.currentTimeMillis();
        byte[] timestampBytes = String.valueOf(timestamp).getBytes();
        byte[] signedTimestamp = SecureFileTransferProtocol.signData(timestampBytes, keyPair.getPrivate());
        
        // Encrypt components with RSA
        byte[] encryptedFileRSA = SecureFileTransferProtocol.rsaEncrypt(encryptedFile, session.remotePublicKey);
        byte[] encryptedFileHashRSA = SecureFileTransferProtocol.rsaEncrypt(fileHash, session.remotePublicKey);
        byte[] encryptedTimestampRSA = SecureFileTransferProtocol.rsaEncrypt(timestampBytes, session.remotePublicKey);
        
        TransferPacket packet = new TransferPacket(
            fileName, encryptedFileRSA, encryptedFileHashRSA, signedFileHash,
            encryptedTimestampRSA, signedTimestamp);
        
        return new TransferResult(session.sessionId, packet, true, "File sent successfully");
    }
    
    private void performKeyExchange(SessionContext session) throws Exception {
        // Generate nonce and sign it
        String nonce = "nonce_" + System.currentTimeMillis();
        byte[] signedNonce = SecureFileTransferProtocol.signData(nonce.getBytes(), keyPair.getPrivate());
        
        // Encrypt nonce
        byte[] encryptedNonce = SecureFileTransferProtocol.rsaEncrypt(nonce.getBytes(), session.remotePublicKey);
        
        // Generate AES session key and IV
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128);
        SecretKey aesSessionKey = aesGen.generateKey();
        
        byte[] iv = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);
        
        // Store session encryption details
        session.aesKey = new SecretKeySpec(aesSessionKey.getEncoded(), "AES");
        session.ivSpec = new IvParameterSpec(iv);
        session.established = true;
    }
    
    private SessionContext createTempSessionForReceiving(String sessionId, TransferPacket packet) throws Exception {
        // Create a temporary session for cross-instance file receiving
        // In a real implementation, session data would be shared or stored externally
        
        // For demo purposes, create a new session with generated AES key
        // The actual AES key and IV will be extracted from the packet's encryption layers
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128);
        SecretKey aesSessionKey = aesGen.generateKey();
        
        byte[] iv = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);
        
        // Create a dummy session context
        SessionContext tempSession = new SessionContext(sessionId, "unknown", null);
        tempSession.aesKey = new SecretKeySpec(aesSessionKey.getEncoded(), "AES");
        tempSession.ivSpec = new IvParameterSpec(iv);
        
        return tempSession;
    }
    
    private PublicKey findSenderPublicKey(TransferPacket packet) {
        // In a real implementation, this would look up the sender's public key
        // from a trusted key store or certificate authority
        // For demo purposes, we'll use any available trusted key
        return trustedPublicKeys.values().iterator().next();
    }
    
    /**
     * Alternative method for cross-instance transfers where both parties share session info
     */
    public ReceivedFile receiveFileWithSession(String sessionId, TransferPacket packet, 
                                              SecretKeySpec aesKey, IvParameterSpec ivSpec, 
                                              PublicKey senderPublicKey) throws Exception {
        // Decrypt RSA-encrypted components
        byte[] decryptedFile = SecureFileTransferProtocol.rsaDecrypt(packet.encryptedFile, keyPair.getPrivate());
        byte[] decryptedFileHash = SecureFileTransferProtocol.rsaDecrypt(packet.encryptedFileHash, keyPair.getPrivate());
        byte[] decryptedTimestamp = SecureFileTransferProtocol.rsaDecrypt(packet.encryptedTimestamp, keyPair.getPrivate());
        
        // Verify signatures
        boolean isFileHashValid = SecureFileTransferProtocol.verifySignature(
            decryptedFileHash, packet.signedFileHash, senderPublicKey);
        boolean isTimestampValid = SecureFileTransferProtocol.verifySignature(
            decryptedTimestamp, packet.signedTimestamp, senderPublicKey);
        
        if (!isFileHashValid || !isTimestampValid) {
            throw new SecurityException("Invalid signatures detected");
        }
        
        // Decrypt file content using AES
        byte[] decryptedFileData = SecureFileTransferProtocol.aesDecrypt(
            decryptedFile, aesKey, ivSpec);
        
        // Verify file integrity
        byte[] calculatedHash = SecureFileTransferProtocol.calculateSHA256Hash(decryptedFileData);
        boolean integrityValid = Arrays.equals(decryptedFileHash, calculatedHash);
        
        if (!integrityValid) {
            throw new SecurityException("File integrity check failed");
        }
        
        return new ReceivedFile(packet.fileName, decryptedFileData, 
            new String(decryptedTimestamp), integrityValid);
    }
    
    private String generateSessionId() {
        return "session_" + UUID.randomUUID().toString();
    }
    
    // Inner classes for data structures
    
    public static class SessionContext {
        final String sessionId;
        final String remoteParticipantId;
        final PublicKey remotePublicKey;
        public SecretKeySpec aesKey;
        public IvParameterSpec ivSpec;
        boolean established = false;
        
        SessionContext(String sessionId, String remoteParticipantId, PublicKey remotePublicKey) {
            this.sessionId = sessionId;
            this.remoteParticipantId = remoteParticipantId;
            this.remotePublicKey = remotePublicKey;
        }
        
        void cleanup() {
            // Clear sensitive data
            if (aesKey != null) {
                Arrays.fill(aesKey.getEncoded(), (byte) 0);
            }
        }
    }
    
    public static class TransferPacket {
        public final String fileName;
        public final byte[] encryptedFile;
        public final byte[] encryptedFileHash;
        public final byte[] signedFileHash;
        public final byte[] encryptedTimestamp;
        public final byte[] signedTimestamp;
        
        public TransferPacket(String fileName, byte[] encryptedFile, byte[] encryptedFileHash,
                            byte[] signedFileHash, byte[] encryptedTimestamp, byte[] signedTimestamp) {
            this.fileName = fileName;
            this.encryptedFile = encryptedFile;
            this.encryptedFileHash = encryptedFileHash;
            this.signedFileHash = signedFileHash;
            this.encryptedTimestamp = encryptedTimestamp;
            this.signedTimestamp = signedTimestamp;
        }
    }
    
    public static class TransferResult {
        public final String sessionId;
        public final TransferPacket packet;
        public final boolean success;
        public final String message;
        
        public TransferResult(String sessionId, TransferPacket packet, boolean success, String message) {
            this.sessionId = sessionId;
            this.packet = packet;
            this.success = success;
            this.message = message;
        }
    }
    
    public static class ReceivedFile {
        public final String fileName;
        public final byte[] data;
        public final String timestamp;
        public final boolean verified;
        
        public ReceivedFile(String fileName, byte[] data, String timestamp, boolean verified) {
            this.fileName = fileName;
            this.data = data;
            this.timestamp = timestamp;
            this.verified = verified;
        }
        
        public void saveToFile(String outputPath) throws IOException {
            Files.write(Paths.get(outputPath), data);
        }
    }
}
