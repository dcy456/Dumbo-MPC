#!/bin/bash

# Get the name of the Ethernet interface
interface=$(ls /sys/class/net | grep -E '^e(n|th)')

# If no suitable interface is found, display a message and exit
if [[ -z "$interface" ]]; then
  echo "No suitable Ethernet interface found"
  exit 1
fi

# Set bandwidth limit to 500 Mbps
rate1="500Mbit"  

# Set burst size to 50 MB
burst1="50mb"  

# Set latency to 75 ms
latency1="75ms"

# Remove any existing traffic control settings on the interface
sudo tc qdisc del dev "$interface" root

# Add a new traffic control rule with delay and rate limit
sudo tc qdisc add dev "$interface" root netem delay "$latency1" rate "$rate1"

# Show current traffic control settings
tc qdisc show
