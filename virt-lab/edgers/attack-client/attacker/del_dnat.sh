#!/bin/bash

# Attacker's private ip
INET_IP=10.8.0.14

# Actual websites IP address
BB_IP=149.28.240.117

# Attacker's public IP
LAN_IP=192.168.254.254


iptables -t nat -D PREROUTING --dst $INET_IP -p tcp --dport 80 -j DNAT --to-destination $BB_IP
iptables -t nat -D POSTROUTING -p tcp --dst $BB_IP --dport 80 -j SNAT --to-source $LAN_IP
