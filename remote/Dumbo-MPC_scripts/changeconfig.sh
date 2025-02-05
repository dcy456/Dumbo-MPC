#!/bin/bash
#cat ips.txt | while read y
#for y in `cat ips.txt`
file="../ip.txt"
ips=$(<"$file")
rm -f .ssh/known_hosts

for ip in $ips
do
    (scp -o "StrictHostKeyChecking no" -i your-key-name.pem ../ip.txt ubuntu@${ip}:~/Dumbo-MPC/hbMPC/scripts/ && scp -i your-key-name.pem ../tc.sh ubuntu@${ip}:~/ &&scp -i your-key-name.pem ../ip.txt ubuntu@${ip}:~/Dumbo-MPC/dumbo-mpc/AsyRanTriGen/scripts/ && scp -i your-key-name.pem ../ip.txt ubuntu@${ip}:~/Dumbo-MPC/dumbo-mpc/OptRanTriGen/scripts/) &
done
