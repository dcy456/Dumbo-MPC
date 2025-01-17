#!/bin/bash
#$1:nodes num
#$1:batchsize

#cat ips.txt | while read y
id=0
file="../ip.txt"
ips=$(<"$file")

mkdir log_${1}_8x
cd log_${1}_8x
mkdir test_${2}
cd ..

for ip in $ips
do
    (scp -i chenghao.pem ubuntu@${ip}:~/Dumbo-mpc/GS23/log/logs-${id}.log ./log_${1}_8x/test_${2}/) &
    let id++
done