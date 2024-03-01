#!/bin/bash

SRCPORT=12345
DSTPORT=80
DSTADDR=192.168.2.254
nping -c 10000 --udp -g $SRCPORT -p $DSTPORT --ttl 4 --source-ip 192.168.3.2 --dest-ip $DSTADDR
