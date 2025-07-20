import java.io.*;
import java.net.*;
import java.util.concurrent.*;

/**
 * Network-based Secure File Transfer Client
 * Handles file transfers over TCP connections
 */
public class SecureFileTransferClient {
    private final SecureFileTransferAPI api;
    private final String host;
    private final int port;
    
    public SecureFileTransferClient(String participantId, String host, int port) throws Exception {
        this.api = new SecureFileTransferAPI(participantId);
        this.host = host;
        this.port = port;
    }
    
    public SecureFileTransferAPI getAPI() {
        return api;
    }
    
    /**
     * Send a file to a remote participant over network
     */
    public boolean sendFileToRemote(String remoteParticipantId, String filePath) throws Exception {
        try (Socket socket = new Socket(host, port);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            
            String sessionId = api.initiateSession(remoteParticipantId);
            
            out.writeObject(new NetworkMessage("INIT_SESSION", sessionId, api.getPublicKey()));
            
            NetworkMessage response = (NetworkMessage) in.readObject();
            if (!"SESSION_ACK".equals(response.type)) {
                throw new RuntimeException("Session initiation failed");
            }
            
            // Send file
            SecureFileTransferAPI.TransferResult result = api.sendFile(sessionId, filePath);
            if (result.success) {
                NetworkMessage fileMessage = new NetworkMessage("FILE_TRANSFER", sessionId, result.packet);
                out.writeObject(fileMessage);
                
                // Wait for confirmation
                NetworkMessage confirmation = (NetworkMessage) in.readObject();
                api.closeSession(sessionId);
                
                return "TRANSFER_SUCCESS".equals(confirmation.type);
            }
            
            return false;
        }
    }
    
    /**
     * Start as a server to receive files
     */
    public void startServer(int listenPort) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(listenPort)) {
            System.out.println("Secure File Transfer Server listening on port " + listenPort);
            
            ExecutorService executor = Executors.newCachedThreadPool();
            
            while (true) {
                Socket clientSocket = serverSocket.accept();
                executor.submit(() -> handleClient(clientSocket));
            }
        }
    }
    
    private void handleClient(Socket clientSocket) {
        try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {
            
            NetworkMessage initMessage = (NetworkMessage) in.readObject();
            if ("INIT_SESSION".equals(initMessage.type)) {
                String sessionId = (String) initMessage.data;
                
                api.addTrustedParticipant("remote_" + sessionId, (java.security.PublicKey) initMessage.publicKey);
                
                out.writeObject(new NetworkMessage("SESSION_ACK", sessionId, null));
                
                NetworkMessage fileMessage = (NetworkMessage) in.readObject();
                if ("FILE_TRANSFER".equals(fileMessage.type)) {
                    try {
                        SecureFileTransferAPI.TransferPacket packet = 
                            (SecureFileTransferAPI.TransferPacket) fileMessage.data;
                        
                        SecureFileTransferAPI.ReceivedFile receivedFile = 
                            api.receiveFile(sessionId, packet);
                        
                        if (receivedFile.verified) {
                            // Save the file
                            String outputPath = "received_" + receivedFile.fileName;
                            receivedFile.saveToFile(outputPath);
                            
                            System.out.println("✓ File received successfully: " + outputPath);
                            out.writeObject(new NetworkMessage("TRANSFER_SUCCESS", sessionId, null));
                        } else {
                            out.writeObject(new NetworkMessage("TRANSFER_FAILED", sessionId, "Verification failed"));
                        }
                        
                        api.closeSession(sessionId);
                        
                    } catch (Exception e) {
                        out.writeObject(new NetworkMessage("TRANSFER_FAILED", sessionId, e.getMessage()));
                    }
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
    
    private static class NetworkMessage implements Serializable {
        public final String type;
        public final Object data;
        public final java.security.PublicKey publicKey;
        
        public NetworkMessage(String type, String sessionId, Object data) {
            this.type = type;
            this.data = data;
            this.publicKey = null;
        }
        
        public NetworkMessage(String type, String sessionId, java.security.PublicKey publicKey) {
            this.type = type;
            this.data = null;
            this.publicKey = publicKey;
        }
    }
}
