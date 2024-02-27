#!/bin/bash
#



apt-get update
apt install net-tools
# /vagrant/remove_ipv6.sh
# sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply
# Configure IPv6
sudo cp /vagrant/ipv6-config/enp0s8.network /etc/systemd/network/
sudo systemctl restart systemd-networkd
# /vagrant/remove_wrong_ipv6_rules
exit
