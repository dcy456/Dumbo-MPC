#!/bin/bash
#$1:nodes num
#$2:batchsize
#$3:test nums
#$4:log type: random triple

#cat ips.txt | while read y
file="../ip.txt"
ips=$(<"$file") 
 
for ip in $ips
do
    (ssh -i your-key-name.pem ubuntu@${ip} -tt "ulimit -n 65536 && killall python") &
done
