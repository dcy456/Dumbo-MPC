#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <task_name> <node_num> <batchsize>"
    exit 1
fi

TASK_NAME=$1
N=$2
k=$3


case "$TASK_NAME" in
    "asy-random")
        echo "Running run_random.py"
        cd ./dumbo-mpc/AsyRanTriGen
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh scripts/run_random.py ${N} ${k}
        ;;
    
    "asy-triple")
        echo "Running run_beaver_triple.py"
        cd ./dumbo-mpc/AsyRanTriGen
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh scripts/run_beaver_triple.py ${N} ${k}
        ;;
    
    "dumbo-mpc")
        echo "Running run_dual_mode.py"
        cd ./dumbo-mpc/dualmode
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh scripts/run_dual_mode.py ${N} ${k}
        ;;
    
    "opt-triple")
        echo "Running optrantrigen.py"
        cd ./dumbo-mpc/OptRanTriGen
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh optimizedhbmpc/optrantrigen.py ${N} ${k}
        ;;
    
    *)
        echo "Invalid task name: $TASK_NAME"
        echo "Valid task names: dumbo-mpc, asy-random, asy-triple, opt-triple"
        exit 1
        ;;
esac
