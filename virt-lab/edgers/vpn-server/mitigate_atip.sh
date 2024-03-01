#!/bin/bash


sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/8  -j SNAT --to-source 192.168.2.133
