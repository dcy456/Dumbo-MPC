#!/bin/bash

# Read the IP addresses from the file
file="./ip.txt"
ips=$(<"$file")

# Loop through each IP address
for ip in $ips
do
    # Transfer the script to the remote machine
    scp -i your-key-name.pem ./tc.sh ubuntu@${ip}:~/ &&  
    # Execute the script on the remote machine
    ssh -i your-key-name.pem ubuntu@${ip} -tt "ulimit -n 65536 && bash tc.sh" &  
done

# Wait for all backgr
