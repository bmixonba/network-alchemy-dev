#!/bin/bash
#




apt-get update
sudo apt-get install openvpn
sudo apt install net-tools
# /vagrant/remove_ipv6.sh

sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

# Configure IPv6
sudo cp /vagrant/ipv6-config/enp0s8.network /etc/systemd/network/
sudo systemctl restart systemd-networkd

# /vagrant/remove_wrong_ipv6_rules
echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf

sysctl -p


exit
