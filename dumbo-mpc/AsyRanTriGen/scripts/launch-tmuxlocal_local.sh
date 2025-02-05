#!/bin/bash

# Exit immediately if any command fails
set -e

# Validate that exactly three arguments are provided
# Usage: ./local_test.sh NUM_NODES NUM_FAULTS SCRIPT_NAME
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <N_value> <f_value> <script_name>"
  echo "Example: $0 4 1 random"
  exit 1
fi

# Assign input arguments to variables
N=$1           # Number of nodes or processes
F=$2           # Fault tolerance or another parameter
SCRIPT_NAME=$3 # Target script name (without "run_" prefix)

# Ensure launch-tmuxlocal.sh has execute permissions
echo "Ensuring launch-tmuxlocal.sh has execute permissions..."
chmod +x ./scripts/launch-tmuxlocal.sh

# Step 1: Run the key generation Python script
echo "Running key generation script with N=$N and f=$F..."
python scripts/run_key_gen.py --N "$N" --f "$F"

# Step 2: Launch the specified Python script using tmux
echo "Launching tmux session for the script: run_$SCRIPT_NAME.py with N=$N..."
./scripts/launch-tmuxlocal.sh /scripts/run_$SCRIPT_NAME.py "$N"

# Indicate that all commands have been successfully executed
echo "All commands executed successfully."
