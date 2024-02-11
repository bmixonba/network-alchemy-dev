sudo iptables -t filter -I OUTPUT -p tcp --sport 80 --tcp-flags RST RST -j DROP
