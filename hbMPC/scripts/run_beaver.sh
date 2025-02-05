#!/bin/bash

id=$3

cd ../AsyRanTriGen/
python scripts/init_batchsize_ip.py --N $1 --k $2 
python -u -m scripts.run_beaver -d -f conf/mpc_$1/local.${id}.json -time 0 
# python -u -m scripts.run_beaver -d -f conf/mpc_$1/local.${id}.json -time 0 >> ../../hbACSS/log/logs-${id}.log