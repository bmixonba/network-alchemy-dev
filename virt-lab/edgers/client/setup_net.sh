#!/bin/bash
#




sudo apt-get update
sudo apt-get install openvpn nmap
sudo apt install net-tools hping3
# /vagrant/remove_ipv6.sh

sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply
# /vagrant/remove_wrong_ipv6_rules
sudo echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf

sudo sysctl -p


exit
