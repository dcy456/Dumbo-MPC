#!/bin/bash
#$1:nodes num
#$2:batch size
#cat ips.txt | while read y
id=0

file="../ip.txt"
ips=$(<"$file")
for ip in $ips
do
    (ssh -i your-key-name.pem ubuntu@${ip} -tt "ulimit -n 65536 && export PATH=/home/ubuntu/.pyenv/shims:\$PATH && cd Dumbo-MPC/dumbo-mpc/ && ./dual_mode.sh $1 $2 ${id}") &
    let id++
done
