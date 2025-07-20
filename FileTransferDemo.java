import java.io.*;
import java.nio.file.*;

/**
 * Demo application showing how to use the SecureFileTransferAPI
 * for file transfers between two parties (Alice and Bob)
 */
public class FileTransferDemo {
    
    public static void main(String[] args) throws Exception {
        System.out.println("=== Secure File Transfer API Demo ===\n");
        
        // Create two participants
        SecureFileTransferAPI alice = new SecureFileTransferAPI("Alice");
        SecureFileTransferAPI bob = new SecureFileTransferAPI("Bob");
        
        // Exchange public keys (in real scenario, this would be done through a secure channel)
        alice.addTrustedParticipant("Bob", bob.getPublicKey());
        bob.addTrustedParticipant("Alice", alice.getPublicKey());
        
        System.out.println("✓ Participants created and public keys exchanged");
        
        // Create a test file to transfer
        String testFileContent = "This is a confidential document from Alice to Bob.\n" +
                "It contains sensitive information that must be protected.\n" +
                "The content is encrypted using AES and verified with SHA-256 hash.\n" +
                "Timestamp: " + System.currentTimeMillis();
        
        String testFileName = "confidential_document.txt";
        createTestFile(testFileName, testFileContent);
        System.out.println("✓ Test file created: " + testFileName);
        
        // Alice initiates a session with Bob
        String sessionId = alice.initiateSession("Bob");
        System.out.println("✓ Secure session established: " + sessionId);
        
        // Alice sends the file to Bob
        System.out.println("\n--- File Transfer Phase ---");
        SecureFileTransferAPI.TransferResult result = alice.sendFile(sessionId, testFileName);
        
        if (result.success) {
            System.out.println("✓ Alice: File encrypted and prepared for transfer");
            System.out.println("  Transfer packet size: " + getTotalPacketSize(result.packet) + " bytes");
            
            // Simulate network transmission (in real scenario, this would go over network)
            System.out.println("📡 Transmitting encrypted file packet...");
            
            // Bob receives and decrypts the file using shared session information
            // Get Alice's session details to share with Bob
            SecureFileTransferAPI.SessionContext aliceSession = alice.getSession(sessionId);
            
            SecureFileTransferAPI.ReceivedFile receivedFile = bob.receiveFileWithSession(
                sessionId, result.packet, aliceSession.aesKey, aliceSession.ivSpec, alice.getPublicKey());
            
            if (receivedFile.verified) {
                System.out.println("✓ Bob: File received and verified successfully");
                System.out.println("  File name: " + receivedFile.fileName);
                System.out.println("  File size: " + receivedFile.data.length + " bytes");
                System.out.println("  Timestamp: " + receivedFile.timestamp);
                
                // Save the received file
                String outputFileName = "received_" + receivedFile.fileName;
                receivedFile.saveToFile(outputFileName);
                System.out.println("✓ File saved as: " + outputFileName);
                
                // Verify content matches
                String receivedContent = new String(receivedFile.data);
                boolean contentMatches = testFileContent.equals(receivedContent);
                System.out.println("✓ Content integrity verified: " + contentMatches);
                
                if (contentMatches) {
                    System.out.println("\n--- Received File Content ---");
                    System.out.println(receivedContent);
                    System.out.println("--- End of Content ---");
                }
                
            } else {
                System.err.println("❌ File verification failed!");
            }
            
        } else {
            System.err.println("❌ File transfer failed: " + result.message);
        }
        
        // Clean up
        alice.closeSession(sessionId);
        bob.closeSession(sessionId);
        System.out.println("\n✓ Session closed and resources cleaned up");
        
        // Clean up test files
        try {
            Files.deleteIfExists(Paths.get(testFileName));
            Files.deleteIfExists(Paths.get("received_" + testFileName));
            System.out.println("✓ Test files cleaned up");
        } catch (Exception e) {
            System.out.println("Note: Could not clean up test files");
        }
        
        System.out.println("\n=== Demo completed successfully! ===");
    }
    
    private static void createTestFile(String fileName, String content) throws IOException {
        Files.write(Paths.get(fileName), content.getBytes());
    }
    
    private static long getTotalPacketSize(SecureFileTransferAPI.TransferPacket packet) {
        return packet.encryptedFile.length + 
               packet.encryptedFileHash.length + 
               packet.signedFileHash.length +
               packet.encryptedTimestamp.length + 
               packet.signedTimestamp.length +
               packet.fileName.getBytes().length;
    }
}
