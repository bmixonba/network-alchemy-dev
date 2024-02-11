#!/bin/bash

####
# This script is intended to run on the victim.
# It overwrites the source port of victim connections to the vpn's listening port.
# This just makes the attack easier to do but is not a neccessary step.
####

sudo iptables -t nat -A POSTROUTING -p udp --dport 1194 -j SNAT --to :31338
