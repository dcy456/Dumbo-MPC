#!/bin/bash
#$1:nodes num

#cat ips.txt | while read y
id=0
file="../ip.txt"
ips=$(<"$file")

for ip in $ips
do
    (scp -i your-key-name.pem ubuntu@${ip}:~/Dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/logs-${id}.log ./log_${1}_8x_5000/) &
    let id++
done
