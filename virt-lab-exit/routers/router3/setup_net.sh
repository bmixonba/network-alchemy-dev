#!/bin/bash
#

apt-get update

sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

#  Disable rp_filter and enable forwarding for routers
#
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s3.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s9.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s10.rp_filter=0" >> /etc/sysctl.conf

sysctl -p

exit
