#!/bin/bash


sudo iptables -t nat -A PREROUTING -p tcp -s 192.168.1.0/24 --dport 80 -j DNAT --to-destination 149.28.240.117:80
