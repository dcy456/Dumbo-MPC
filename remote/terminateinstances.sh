#!/bin/bash
for y in `cat instanceids.txt`
do
    aws ec2 terminate-instances --instance-ids $y
done