#!/bin/bash

# Ensure NUM_NODES argument is passed
if [ $# -lt 1 ]; then
    echo "Usage: $0 <NUM_NODES>"
    exit 1
fi

NUM_NODES=$1
LOG_DIR="../AsyRanTriGen/log"  # Adjust the path to your logs directory if needed

# Check if the log directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "Log directory $LOG_DIR does not exist."
    exit 1
fi

# Array to store the status of each log file
declare -A log_status

# Initialize log status for all logs
for ID in $(seq 0 $((NUM_NODES - 1))); do
    log_status[$ID]=false
done

# Monitor logs until 'Finished' is found in all log files
# echo "Monitoring logs for 'Finished'..."

# Loop to check logs
while true; do
    all_finished=true
    # Check each log file for 'Finished' keyword
    for ID in $(seq 0 $((NUM_NODES - 1))); do
        LOG_FILE="$LOG_DIR/logs-${ID}.log"
        
        # Check if the 'Finished' keyword appears in the log file
        if grep -q "Finished" "$LOG_FILE"; then
            # echo "'Finished' found in $LOG_FILE"
            log_status[$ID]=true
        fi
        
        # If any log file does not have 'Finished', set all_finished to false
        if [ "${log_status[$ID]}" = false ]; then
            all_finished=false
        fi
    done
    
    # If all logs contain 'Finished', exit the loop
    if [ "$all_finished" = true ]; then
        break
    fi
    
    # Sleep before checking again
    sleep 1
done

# echo "'Finished' detected in all log files. Exiting script."
exit 0  # Explicitly exit with a success code
