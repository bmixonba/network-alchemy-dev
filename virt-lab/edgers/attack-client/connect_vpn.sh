#!/bin/bash

sudo openvpn --config /vagrant/client2.ovpn --daemon
sleep 1
sudo ip route add 192.168.3.254 dev tun0
