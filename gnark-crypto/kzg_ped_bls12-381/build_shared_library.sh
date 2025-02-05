#!/bin/bash

# "Build the shared library kzg_ped_out.so"
echo "Building kzg_ped_out.so..."
go build -o kzg_ped_out.so -buildmode=c-shared kzg_ped_out.go
if [ $? -ne 0 ]; then
    echo "Build failed. Exiting..."
    exit 1
fi
echo "Build successful: kzg_ped_out.so created."

# "Define the target directory for copying the script"
# TARGET_DIR="../../../dumbo-mpc/AsyRanTriGen/"
TARGET_DIR="../../dumbo-mpc/AsyRanTriGen/"

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
cp "kzg_ped_out.so" "$TARGET_DIR"
if [ $? -ne 0 ]; then
    echo "Failed to copy script. Exiting..."
    exit 1
fi
echo "Script successfully copied to $TARGET_DIR."

# "Indicate completion"
echo "Done."
