# Secure File Transfer Protocol

A comprehensive secure file transfer system implementing RSA and AES encryption with digital signatures for authentication and integrity verification.

## Overview

This project provides:

1. **Core Protocol** (`SecureFileTransferProtocol.java`) - Low-level cryptographic operations
2. **High-level API** (`SecureFileTransferAPI.java`) - Easy-to-use interface for secure file transfers
3. **Network Support** (`SecureFileTransferClient.java`) - TCP-based network file transfers
4. **Demo Applications** - Various examples showing usage

## Features

- **Hybrid Encryption**: RSA for key exchange, AES for file encryption
- **Digital Signatures**: SHA256withRSA for authentication and integrity
- **Session Management**: Secure session establishment and cleanup
- **Network Support**: TCP-based file transfers
- **File Integrity**: SHA-256 hash verification
- **Timestamp Verification**: Prevents replay attacks

## Security Features

- 2048-bit RSA key pairs for asymmetric encryption
- 128-bit AES encryption for file data
- SHA-256 hash verification for file integrity
- Digital signatures for authentication
- Secure random IV generation
- Session-based security contexts

## Building and Running

### Build the Project

```bash
./build.sh
```

Or manually:
```bash
javac *.java
```

### 1. Basic Protocol Demo

Shows the underlying cryptographic protocol:

```bash
java SecureFileTransferProtocol
```

### 2. API Demo

Demonstrates the high-level API for local file transfers:

```bash
java FileTransferDemo
```

### 3. Network Transfer Demo

#### Local Demo (Recommended)
Runs both client and server locally:

```bash
java NetworkTransferDemo demo
```

#### Manual Network Setup

Start a server:
```bash
java NetworkTransferDemo server 8080
```

Send a file from another terminal:
```bash
java NetworkTransferDemo client localhost 8080 ServerID myfile.txt
```

## API Usage

### Basic File Transfer

```java
// Create participants
SecureFileTransferAPI alice = new SecureFileTransferAPI("Alice");
SecureFileTransferAPI bob = new SecureFileTransferAPI("Bob");

// Exchange public keys
alice.addTrustedParticipant("Bob", bob.getPublicKey());
bob.addTrustedParticipant("Alice", alice.getPublicKey());

// Establish session
String sessionId = alice.initiateSession("Bob");

// Send file
SecureFileTransferAPI.TransferResult result = alice.sendFile(sessionId, "document.txt");

// Receive file
SecureFileTransferAPI.ReceivedFile file = bob.receiveFile(sessionId, result.packet);

// Save received file
file.saveToFile("received_document.txt");

// Cleanup
alice.closeSession(sessionId);
```

### Network Transfer

```java
// Server side
SecureFileTransferClient server = new SecureFileTransferClient("Server", "localhost", 8080);
server.startServer(8080);

// Client side
SecureFileTransferClient client = new SecureFileTransferClient("Client", "localhost", 8080);
boolean success = client.sendFileToRemote("Server", "myfile.txt");
```

## Protocol Flow

1. **Key Generation**: Each participant generates RSA key pairs
2. **Key Exchange**: Public keys are exchanged securely
3. **Session Initiation**: Nonce-based authentication
4. **AES Key Exchange**: Symmetric key generation and secure distribution
5. **File Transfer**: 
   - File is hashed with SHA-256
   - File is encrypted with AES
   - Hash is signed with sender's private key
   - Everything is encrypted with recipient's public key
6. **Verification**: Recipient verifies signatures and file integrity

## File Structure

```
├── SecureFileTransferProtocol.java  # Core cryptographic protocol
├── SecureFileTransferAPI.java       # High-level API
├── SecureFileTransferClient.java    # Network client/server
├── FileTransferDemo.java            # Local API demo
├── NetworkTransferDemo.java         # Network demo
├── build.sh                         # Build script
└── README.md                        # This file
```

## Security Considerations

- **Key Management**: In production, implement proper key distribution and verification
- **Certificate Authority**: Consider using PKI for public key authentication
- **Network Security**: Use TLS for network transport in production
- **Key Storage**: Secure storage of private keys
- **Access Control**: Implement proper authentication and authorization

## Requirements

- Java 8 or higher
- No external dependencies (uses built-in Java cryptography)

## Troubleshooting

### Common Issues

1. **Build Errors**: Ensure you have Java 8+ and JAVA_HOME is set
2. **Network Issues**: Check firewall settings for TCP connections
3. **File Permissions**: Ensure read/write permissions for file operations

### Error Messages

- `"Invalid session ID"`: Session expired or not initialized
- `"Unknown participant"`: Public key not added to trusted participants
- `"Invalid signatures detected"`: Signature verification failed
- `"File integrity check failed"`: File was corrupted during transfer

## License

See LICENSE file for details.
