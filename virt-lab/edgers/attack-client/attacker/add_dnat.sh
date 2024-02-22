#!/bin/bash

# Attacker's private ip
INET_IP=10.8.0.6

# Actual websites IP address
BB_IP=149.28.240.117

# Attacker's public IP
LAN_IP=192.168.254.254


# Usually I put this after
# iptables -t nat -$1 POSTROUTING -o tun0 -j MASQUERADE
# iptables -t nat -$1 POSTROUTING -o enp0s8 -j MASQUERADE

sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 149.28.240.117:80
sudo iptables -t nat -A POSTROUTING -j MASQUERADE

# iptables -t nat -A POSTROUTING -s $BB_IP -j SNAT --to-destination 192.168.1.254 
# Not sure this rule is needed.
# iptables -t nat -$1 POSTROUTING -p tcp -s $BB_IP --dport 80 -j MASQUERADE 
