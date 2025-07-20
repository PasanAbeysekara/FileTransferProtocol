import java.io.*;
import java.nio.file.*;

/**
 * Demo for network-based secure file transfer
 */
public class NetworkTransferDemo {
    
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return;
        }
        
        String mode = args[0].toLowerCase();
        
        switch (mode) {
            case "server":
                runServer(args);
                break;
            case "client":
                runClient(args);
                break;
            case "demo":
                runLocalDemo();
                break;
            default:
                printUsage();
        }
    }
    
    private static void runServer(String[] args) throws Exception {
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 8080;
        
        System.out.println("Starting Secure File Transfer Server...");
        SecureFileTransferClient server = new SecureFileTransferClient("Server", "localhost", port);
        server.startServer(port);
    }
    
    private static void runClient(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Client mode requires: host port remoteId filePath");
            return;
        }
        
        String host = args[1];
        int port = Integer.parseInt(args[2]);
        String remoteId = args[3];
        String filePath = args[4];
        
        if (!Files.exists(Paths.get(filePath))) {
            System.err.println("File not found: " + filePath);
            return;
        }
        
        System.out.println("Connecting to " + host + ":" + port);
        SecureFileTransferClient client = new SecureFileTransferClient("Client", host, port);
        
        // For demo purposes -> add a dummy public key for the remote server
        // In real scenario -> exchange and verify public keys securely
        boolean success = client.sendFileToRemote(remoteId, filePath);
        
        if (success) {
            System.out.println("File sent successfully!");
        } else {
            System.err.println("File transfer failed!");
        }
    }
    
    private static void runLocalDemo() throws Exception {
        System.out.println("=== Local Network Transfer Demo ===\n");
        
        String testFile = "demo_file.txt";
        String content = "This is a test file for network transfer demo.\n" +
                        "It will be sent securely over TCP connection.\n" +
                        "Timestamp: " + System.currentTimeMillis();
        
        Files.write(Paths.get(testFile), content.getBytes());
        System.out.println("✓ Created test file: " + testFile);
        
        Thread serverThread = new Thread(() -> {
            try {
                SecureFileTransferClient server = new SecureFileTransferClient("DemoServer", "localhost", 8080);
                server.startServer(8080);
            } catch (Exception e) {
                System.err.println("Server error: " + e.getMessage());
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        
        Thread.sleep(2000);
        System.out.println("✓ Server started on port 8080");
        
        try {
            SecureFileTransferClient client = new SecureFileTransferClient("DemoClient", "localhost", 8080);
            boolean success = client.sendFileToRemote("DemoServer", testFile);
            
            if (success) {
                System.out.println("✓ File transfer completed successfully!");
                
                String receivedFile = "received_" + testFile;
                if (Files.exists(Paths.get(receivedFile))) {
                    String receivedContent = new String(Files.readAllBytes(Paths.get(receivedFile)));
                    boolean contentMatches = content.equals(receivedContent);
                    System.out.println("✓ Content verification: " + (contentMatches ? "PASSED" : "FAILED"));
                    
                    Files.deleteIfExists(Paths.get(testFile));
                    Files.deleteIfExists(Paths.get(receivedFile));
                    System.out.println("✓ Cleanup completed");
                }
            } else {
                System.err.println("❌ File transfer failed!");
            }
            
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
        
        System.out.println("\n=== Demo completed ===");
        System.exit(0);
    }
    
    private static void printUsage() {
        System.out.println("Secure File Transfer Network Demo");
        System.out.println("Usage:");
        System.out.println("  java NetworkTransferDemo server [port]");
        System.out.println("  java NetworkTransferDemo client <host> <port> <remoteId> <filePath>");
        System.out.println("  java NetworkTransferDemo demo");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java NetworkTransferDemo server 8080");
        System.out.println("  java NetworkTransferDemo client localhost 8080 ServerID myfile.txt");
        System.out.println("  java NetworkTransferDemo demo");
    }
}
