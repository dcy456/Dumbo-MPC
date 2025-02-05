#!/bin/bash
#$1:nodes num
#$2:batchsize
#$3:node id

id=$3


cd ../OptRanTriGen
python scripts/init_batchsize_ip.py --N ${NUM_NODES} --k ${batchsize}
cd ../dualmode

python -u -m scripts.run_dual_mode -d -f conf/mpc_$1/local.${id}.json  > log/logs-${id}.log