#!/bin/bash

ip route add 192.168.1.0/24 dev tun0
ip route add 192.168.3.0/24 dev tun0
