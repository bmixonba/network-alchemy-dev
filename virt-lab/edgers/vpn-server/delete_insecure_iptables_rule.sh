#!/bin/bash

sudo iptables -t nat -D POSTROUTING -s 10.0.0.0/8 -o enp0s8 -j MASQUERADE
