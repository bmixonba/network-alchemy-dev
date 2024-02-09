#/bin/bash
#


echo Adding nat iptables rules to route traffic through mitmproxy..

sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 443 -j REDIRECT --to-port 8080



echo Adding redirect to real server rules..

REDIRECT_IP=157.240.2.35

sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.2.2 --destination-port 80 -j DNAT --to-destination $REDIRECT_IP
sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.2.2 --destination-port 443 -j DNAT --to-destination $REDIRECT_IP
