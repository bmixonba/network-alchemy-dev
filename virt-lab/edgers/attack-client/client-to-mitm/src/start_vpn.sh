#!/bin/bash

sudo openvpn --config /vagrant/client2.ovpn --daemon
sudo ip route add 192.168.1.0/24 dev tun0
