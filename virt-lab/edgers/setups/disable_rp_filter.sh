#!/bin/bash

printf "Disabling rp filter on local interfaces..\n"

sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
sudo sysctl -w net.ipv4.conf.enp0s8.rp_filter=0
sudo sysctl -w net.ipv4.conf.lo.rp_filter=0




