#!/bin/bash
#$1:nodes num
#$2:batchsize
#$3:node id

id=$3

cd ./OptRanTriGen/
python scripts/init_batchsize_ip.py --N $1 --k $2 
python -u -m scripts.run_dual_mode -d -f conf/mpc_$1/local.${id}.json  > log/logs-${id}.log