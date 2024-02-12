#!/bin/bash


INET_IP=$1
HTTP_IP=149.28.240.117
SIP=192.168.1.254 #192.168.2.254 

# sudo iptables -t nat -A PREROUTING -i tun0 -s $SIP -p tcp --dport 80 -j DNAT --to-destination $HTTP_IP
# sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE 
# sudo iptables -t nat -A POSTROUTING  -p tcp --dst $HTTP_IP --dport 80 -j SNAT --to-source 192.168.1.5

# sudo iptables -t nat -A OUTPUT --dst $INET_IP -p tcp --dport 80  -j DNAT --to-destination $HTTP_IP



# DNAT: Change the destination IP address for the incoming packet
sudo iptables -t nat -A PREROUTING -i tun0 -s $SIP -p tcp --dport 80 -j DNAT --to-destination 149.28.240.117
sudo iptables -t nat -A POSTROUTING -s 149.28.240.117 -p tcp -j SNAT --to $SIP

# sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --sport 80 -j DNAT --to-destination 192.168.0.5
# sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE


# sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --source 149.28.240.117 --sport 80 -j DNAT --to-destination 192.168.0.5
# sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --sport 80 -j DNAT --to-destination 192.168.0.5
# sudo iptables -t nat -A POSTROUTING -tun0 -j MASQUERADE
