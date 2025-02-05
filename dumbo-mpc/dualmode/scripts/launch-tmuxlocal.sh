#!/bin/bash

set -e  # fail if any command fails

# This script runs an MPC program in N processes.
# Usage: scripts/launch-tmuxlocal.sh optimizedhbmpc/ipc.py 4

if [ $# -lt 2 ] ; then
    echo "usage: $0 <module.py> <NUM_NODES>"
    echo "example: $0 optimizedhbmpc/ipc.py 4"
    exit 1
fi

if [ -z "$1" ]
  then
    echo "MPC file to run not specified."
fi

if [ -z "$2" ]
  then
    echo "MPC config file prefix not specified."
fi

# Change dir/file.py to dir.file
FILE_PATH=$1
DIRS=(${FILE_PATH//\// })
DOT_SEPARATED_PATH=$(IFS=. ; echo "${DIRS[*]}")
MODULE_PATH=${DOT_SEPARATED_PATH::-3}
echo MODULE_PATH
# CONFIG_PATH=$2

NUM_NODES=$2
# CONFIG_PATH="conf/mpc_${NUM_NODES}/local"
CONFIG_PATH="../OptRanTriGen/conf/mpc_${NUM_NODES}/local"

CMD="python -m ${MODULE_PATH}"
echo ">>> Command to be executed: '${CMD}'"
# Create simulated latency using tc
# scripts/latency-control.sh stop
# scripts/latency-control.sh start 20ms 5ms

## TODO: the following was used for launching a larger number
## of processes locally, with only a portion of them shown in tmux
# for ID in $(seq 4 49)
for ID in $(seq 4 $NUM_NODES)
do
   echo
   ${CMD} -d -f ${CONFIG_PATH}.${ID}.json -time $start_time > log/logs-${ID}.log 2>&1 &
done

if [ -z "$3" ]
  then
    # set -x
    # rm -rf sharedata/
    # tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json > log/logs-0.log; sh" \; \
    #     splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json > log/logs-1.log; sh" \; \
    #     splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.2.json > log/logs-2.log; sh" \; \
    #     selectp -t 0 \; \
    #     splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.3.json > log/logs-3.log; sh"
    set -x
    rm -rf sharedata/
    tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json; sh" \; \
        splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json; sh" \; \
        splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.2.json; sh" \; \
        selectp -t 0 \; \
        splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.3.json; sh"

elif [ "$3" == "dealer" ]
  then
    set -x
    rm -rf sharedata/
    tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json; sh" \; \
        splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json; sh" \; \
        splitw -v -p 50 "sleep 2; ${CMD} -d -f ${CONFIG_PATH}.2.json; sh" \; \
        selectp -t 0 \; \
        splitw -v -p 50 "sleep 4; ${CMD} -d -f ${CONFIG_PATH}.3.json; sh" \; \
        splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.4.json; sh"
fi
