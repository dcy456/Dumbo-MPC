#!/bin/bash
#$1:nodes num
#$2:batch size
#cat ips.txt | while read y
id=0

file="../ip.txt"
ips=$(<"$file")
for ip in $ips
do
    (ssh -i your-key-name.pem ubuntu@${ip} -tt "ulimit -n 65536 && export PATH=/home/ubuntu/.pyenv/shims:\$PATH && cd ./Dumbo-mpc/dumbo-mpc/OptRanTriGen/ && python scripts/init_batchsize_ip.py --N $1 --k $2 && nohup python -u -m honeybadgermpc.optrantrigen -d -f conf/mpc_$1/local.${id}.json -time 0 > log/logs-${id}.log") &
    let id++
done
