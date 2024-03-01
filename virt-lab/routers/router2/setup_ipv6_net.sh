#!/bin/bash
#

# /vagrant/remove_ipv6.sh
# sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.ipv6.yaml /etc/netplan/
sudo netplan apply

# Configure IPv6
sudo cp /vagrant/ipv6-config/enp0s8.network /etc/systemd/network/enp0s8.network
sudo systemctl restart systemd-networkd
# /vagrant/remove_wrong_ipv6_rules
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s3.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf
# echo "net.ipv4.conf.enp0s9.rp_filter=0" >> /etc/sysctl.conf

sysctl -p
sudo apt-get update -y
sudo apt install net-tools dos2unix -y
sudo cp /vagrant/radvd.conf /etc/radvd.conf
sudo dos2unix /etc/radvd.conf
sudo apt install radvd -y
exit
