#!/bin/bash

# Get a list of all network interfaces excluding enp0s3
interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'enp0s3')

# Loop through each interface and remove IPv6 addresses
for interface in $interfaces; do
    # Remove IPv6 addresses
    sudo ip -6 addr flush dev $interface
done
