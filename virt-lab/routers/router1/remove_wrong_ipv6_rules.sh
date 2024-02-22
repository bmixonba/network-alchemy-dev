#! /bin/bash

sudo ip -6 route del fd00::/8 dev enp0s8
sudo ip -6 route del fd00::/8 dev enp0s9
sudo ip -6 route del fd00::/8 dev enp0s16
sudo ip -6 route del fd00::/8 dev enp0s10
sudo ip -6 route add fd01::/32 dev enp0s8
sudo ip -6 route add fd02::/32 dev enp0s9
sudo ip -6 route add fd03::/32 dev enp0s10
sudo ip -6 route add fd04::/32 dev enp0s16
sudo ip -6 route add fdfe::/32  via fd04::fe dev enp0s16