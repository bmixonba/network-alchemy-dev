#!/bin/bash
#

apt-get update

sed -i "s/#VAGRANT-END/up route add -net 192.168.0.0\/16 gw 192.168.1.254 dev enp0s8/g" /etc/network/interfaces

sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

# apt-get update
apt-get install traceroute # quagga quagga-doc traceroute
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s3.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s9.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s10.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s16.rp_filter=0" >> /etc/sysctl.conf
sysctl -p
sudo apt install net-tools -y

exit
