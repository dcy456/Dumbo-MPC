#!/bin/bash
set -e  # Exit immediately if any command fails

# This script runs an MPC program in N processes.
# Usage: scripts/launch-tmuxlocal.sh module.py NUM_NODES

if [ $# -lt 2 ]; then
    echo "Usage: $0 <module.py> <num_nodes>"
    echo "Example: $0 scripts/run_beaver.py 4"
    exit 1
fi

# Get input arguments
FILE_PATH=$1
NUM_NODES=$2

# Convert dir/file.py to dir.file
DIRS=(${FILE_PATH//\// })
DOT_SEPARATED_PATH=$(IFS=. ; echo "${DIRS[*]}")
MODULE_PATH=${DOT_SEPARATED_PATH::-3} # Remove ".py" extension

# Configuration path based on the number of nodes
CONFIG_PATH="conf/mpc_${NUM_NODES}/local"

# Python command
CMD="python -m ${MODULE_PATH}"

# Start time for processes
start_time=$(date +%s)
start_time=$((start_time + 2))

# Create a logs directory if it doesn't exist
mkdir -p log

# Array to store process IDs
PIDS=()

# Run all nodes in the background and log output
for ID in $(seq 0 $((NUM_NODES - 1))); do
    echo "Starting node $ID..."
    ${CMD} -d -f ${CONFIG_PATH}.${ID}.json -time $start_time &> log/logs-${ID}.log &
    PIDS+=($!) # Store process ID
done

# Wait for 10 seconds
sleep 10

# Kill all Python processes
echo "Terminating all nodes ..."
for IDX in "${!PIDS[@]}"; do
    kill -9 "${PIDS[$IDX]}" && echo "Terminated node $IDX"
done

echo "All node processes terminated. Logs are stored in the 'GS23/log/' directory."