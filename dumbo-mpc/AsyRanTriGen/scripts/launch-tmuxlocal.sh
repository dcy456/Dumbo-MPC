#!/bin/bash
set -e  # fail if any command fails

# This script runs an MPC program in N processes.

# Usage: scripts/launch-tmuxlocal.sh scripts/run_random.py NUM_NODES

if [ $# -lt 2 ] ; then
    echo "usage: $0 <module.py> <conf>"
    echo "example: $0 honeybadgermpc/ipc.py conf/mpc/local"
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

# CONFIG_PATH=$2

NUM_NODES=$2
CONFIG_PATH="conf/mpc_${NUM_NODES}/local"

CMD="python -m ${MODULE_PATH}"
echo ">>> Command to be executed: '${CMD}'"

start_time=$(date +%s)
start_time=$((start_time+2))

# Create simulated latency using tc
# scripts/latency-control.sh stop
# scripts/latency-control.sh start 20ms 5ms

## TODO: the following was used for launching a larger number
## of processes locally, with only a portion of them shown in tmux
# for ID in $(seq 4 $NUM_NODES)
# do
#    echo
#   #  ${CMD} -d -f ${CONFIG_PATH}.${ID}.json -time $start_time > log/logs-${ID}.log 2>&1 &
#    ${CMD} -d -f ${CONFIG_PATH}.${ID}.json -time $start_time > log/logs-${ID}.log &
# done

# sleep 3s
if [ -z "$3" ]
  then
    set -x
    rm -rf sharedata/
    # tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json -time $start_time 2> log/logs-0.log; sh" \; \
    #     splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json -time $start_time 2> log/logs-1.log; sh" \; \
    #     splitw -v -p 66 "${CMD} -d -f ${CONFIG_PATH}.2.json -time $start_time 2> log/logs-2.log; sh" \; \
    #     splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.3.json -time $start_time 2> log/logs-3.log; sh" \;

    tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json -time $start_time > log/logs-0.log; sh" \; \
        splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json -time $start_time > log/logs-1.log; sh" \; \
        splitw -v -p 66 "${CMD} -d -f ${CONFIG_PATH}.2.json -time $start_time > log/logs-2.log; sh" \; \
        splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.3.json -time $start_time > log/logs-3.log; sh" \;
    # tmux new-session     "${CMD} -d -f ${CONFIG_PATH}.0.json -time $start_time ; sh" \; \
    #     splitw -h -p 50 "${CMD} -d -f ${CONFIG_PATH}.1.json -time $start_time ; sh" \; \
    #     splitw -v -p 66 "${CMD} -d -f ${CONFIG_PATH}.2.json -time $start_time ; sh" \; \
    #     splitw -v -p 50 "${CMD} -d -f ${CONFIG_PATH}.3.json -time $start_time ; sh" \;
fi
