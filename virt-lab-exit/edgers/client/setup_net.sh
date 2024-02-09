#!/bin/bash
#




apt-get update
sudo apt-get install openvpn
sudo apt install net-tools
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf

sysctl -p


exit
