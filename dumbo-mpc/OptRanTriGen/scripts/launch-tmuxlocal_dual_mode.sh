#!/bin/bash
#$1:nodes num
#$2:batchsize

set -e  # fail if any command fails

# This script runs an MPC program in N processes.




NUM_NODES=$1
BATCH_SIZE=$2

cd ..
CMD="./Dual_Mode_Tri_Gen.sh $1 $2"
echo ">>> Command to be executed: '${CMD}'"

## TODO: the following was used for launching a larger number
## of processes locally, with only a portion of them shown in tmux
# for ID in $(seq 4 49
# for ID in $(seq 4 $NUM_NODES)
# do
#    echo
#    ${CMD} ${ID} &
# done

if [ -z "$3" ]
  then
    set -x
    rm -rf sharedata/
    tmux new-session     "${CMD} 0" \; \
        splitw -h -p 50 "${CMD} 1" \; \
        splitw -v -p 50 "${CMD} 2" \; \
        selectp -t 0 \; \
        splitw -v -p 50 "${CMD} 3"

fi

