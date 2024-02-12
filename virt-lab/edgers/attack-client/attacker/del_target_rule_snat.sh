#!/bin/bash


INET_IP=$1
HTTP_IP=149.28.240.117
VICTIM_IP=192.168.1.254

sudo iptables -t nat -D PREROUTING -i tun0 -p tcp --dport 80 -j DNAT --to-destination $HTTP_IP
sudo iptables -t nat -D POSTROUTING  -p tcp --dst $HTTP_IP --dport 80 -j SNAT --to-source $VICTIM_IP

# sudo iptables -t nat -A OUTPUT --dst $INET_IP -p tcp --dport 80  -j DNAT --to-destination $HTTP_IP

