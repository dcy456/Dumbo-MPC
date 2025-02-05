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
cd ../AsyRanTriGen/ || { echo "Failed to change directory to ../AsyRanTriGen/"; exit 1; }

# # Initialize batch size and IP configuration for random shares (if needed)
# python3 scripts/init_batchsize_ip.py --N ${NUM_NODES} --k ${k}

if [ $? -ne 0 ]; then
    echo "Failed to initialize batch size and IP configuration for random shares."
    exit 1
fi

# Execute the second command to generate random shares
echo "Generating random shares using command './scripts/local_test.sh scripts/run_random.py $NUM_NODES'"
./scripts/local_test.sh scripts/run_random.py "$NUM_NODES" "$k"

if [ $? -ne 0 ]; then
    echo "Failed to generate random shares."
    exit 1
fi

# Calculate required_triple using Python
required_triple=$(python3 -c "import math; print(2 * $k * int(math.log($k, 2)) ** 2)")
echo "Number of required triples: $required_triple"
secret_batchsize=$(python3 -c "import math; print(math.ceil(2 * $k * int(math.log($k, 2)) ** 2 / 10))")
echo "Number of secre to be shared: $secret_batchsize"


cd ../dualmode/ || { echo "Failed to change directory to ../dualmode/"; exit 1; }
./scripts/local_test.sh scripts/run_dual_mode.py "$NUM_NODES" "$secret_batchsize"

# if [ $? -ne 0 ] || [ -z "$required_triple" ]; then
#     echo "Failed to calculate required_triple using Python."
#     exit 1
# fi

cd ../online/
# parse random and triples format for online evaluaiton
python scripts/parse_asy_ran_triples.py --N "$NUM_NODES"

python scripts/parse_fast_path_triple.py --N "$NUM_NODES"

#generate one_minus_ones'shares for online evaluaiton 
python scripts/one_minus_one_generation.py --N "$NUM_NODES" --k "$k"

# mv ./sharedata/* ./sharedata_test/

cd ../OptRanTriGen/
python scripts/init_batchsize_ip.py --N "$NUM_NODES" --k "$k"

echo "All proprecessing data store at /online/sharedata_test."