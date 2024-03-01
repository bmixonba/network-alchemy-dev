#!/bin/bash

SRCPORT=80
DSTPORT=12345
DSTADDR=192.168.3.2
nping -c 100 --udp -g $SRCPORT -p $DSTPORT --ttl 2 --dest-ip $DSTADDR
