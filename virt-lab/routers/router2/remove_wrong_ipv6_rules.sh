#! /bin/bash

sudo ip -6 route del fd00::/8 dev enp0s8
sudo ip -6 route del fd00::/8 dev enp0s9
sudo ip -6 route add fdfe::/16 dev enp0s9
sudo ip -6 route add fd04::/16 dev enp0s8
sudo ip -6 route add fd00::/8 via fd04::2 dev enp0s8
