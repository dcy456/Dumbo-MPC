#!/bin/bash

# "Build the shared library secp256k1_pedersen_out.go"
echo "Building secp256k1_pedersen_out.go..."
go build -o pedersen_out.so -buildmode=c-shared  secp256k1_pedersen_out.go
if [ $? -ne 0 ]; then
    echo "Build failed. Exiting..."
    exit 1
fi
echo "Build successful: secp256k1_pedersen_out.go created."

# "Define the target directory for copying the script"
TARGET_DIR="../../GS23"

# "Check if the target directory exists; create it if not"
if [ ! -d "$TARGET_DIR" ]; then
    echo "Target directory does not exist. Creating it..."
    mkdir -p "$TARGET_DIR"
    if [ $? -ne 0 ]; then
        echo "Failed to create target directory. Exiting..."
        exit 1
    fi
fi

# "Copy the script to the target directory"
echo "Copying script to target directory..."
cp "$0" "$TARGET_DIR"
if [ $? -ne 0 ]; then
    echo "Failed to copy script. Exiting..."
    exit 1
fi
echo "Script successfully copied to $TARGET_DIR."

# "Indicate completion"
echo "Done."
