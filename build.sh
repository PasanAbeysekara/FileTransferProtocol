#!/bin/bash

# Secure File Transfer Protocol Build Script

echo "Building Secure File Transfer Protocol..."

# Clean previous builds
echo "Cleaning previous builds..."
rm -f *.class

# Compile all Java files
echo "Compiling Java files..."
javac -cp . *.java

if [ $? -eq 0 ]; then
    echo "✓ Build successful!"
    echo ""
    echo "Available programs:"
    echo "1. Basic protocol demo:     java SecureFileTransferProtocol"
    echo "2. API demo:               java FileTransferDemo"
    echo "3. Network transfer demo:   java NetworkTransferDemo demo"
    echo "4. Network server:         java NetworkTransferDemo server [port]"
    echo "5. Network client:         java NetworkTransferDemo client <host> <port> <remoteId> <file>"
    echo ""
    echo "Example usage:"
    echo "  java FileTransferDemo"
    echo "  java NetworkTransferDemo demo"
else
    echo "❌ Build failed!"
    exit 1
fi
