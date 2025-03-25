#!/bin/bash
set -e  # Exit immediately if any command fails

# This script runs an MPC program in N processes.
# Usage: scripts/launch-tmuxlocal.sh module.py NUM_NODES

if [ $# -lt 2 ]; then
    echo "Usage: $0 <module.py> <num_nodes> <batchsize>"
    echo "Example: $0 scripts/run_dual_mode.py 4 16"
    exit 1
fi

# Get input arguments
FILE_PATH=$1
NUM_NODES=$2

batchsize=$3

cd ../OptRanTriGen
python scripts/init_batchsize_ip.py --N ${NUM_NODES} --k ${batchsize}
cd ../dualmode

# Convert dir/file.py to dir.file
DIRS=(${FILE_PATH//\// })
DOT_SEPARATED_PATH=$(IFS=. ; echo "${DIRS[*]}")
MODULE_PATH=${DOT_SEPARATED_PATH::-3} # Remove ".py" extension

# Configuration path based on the number of nodes
CONFIG_PATH="../OptRanTriGen/conf/mpc_${NUM_NODES}/local"

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
    ${CMD} -d -f ${CONFIG_PATH}.${ID}.json > log/logs-${ID}.log &
    PIDS+=($!) # Store process ID
done

# Start monitoring the logs for the 'Finished' keyword
# echo "Starting to monitor log files for 'Finished' keyword..."
./scripts/monitor_log.sh "$NUM_NODES" &  # Run monitor_log.sh in the background

# Wait for the log monitoring script to finish
wait $!  # Wait for monitor_log.sh to finish before continuing

# Kill all Python processes
echo "Terminating all nodes ..."
for PID in $(pgrep -f "scripts.run_beaver"); do
    kill -9 "$PID"
done
for IDX in "${!PIDS[@]}"; do
    kill -9 "${PIDS[$IDX]}" && echo "Terminated node $IDX"
done

echo "All node processes terminated. Logs are stored in the 'dumbo-mpc/dualmode/log/' directory."
