#!/bin/bash

id=$3

cd ../AsyRanTriGen/
python scripts/init_batchsize_ip_per_node.py --N $1 --id $3 --k $2 
python -u -m scripts.run_beaver -d -f conf/mpc_$1/local.${id}.json -time 0 