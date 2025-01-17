#!/bin/bash

# Check if the number of arguments is correct
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <number_of_nodes> <k_value>"
    exit 1
fi

# Store the arguments passed to the script
NUM_NODES=$1
k=$2

# Change directory to ../AsyRanTriGen/
cd ../OptRanTriGen/ || { echo "Failed to change directory to ../OptRanTriGen/"; exit 1; }

./scripts/local_test.sh apps/asynchromix/butterfly_network.py "$NUM_NODES" "$k"