#!/bin/bash
#

sudo apt-get update
sudo apt install nmap conntrack

sudo sed -i "s/#VAGRANT-END/up route add -net 192.168.0.0\/16 gw 192.168.1.254 dev enp0s8/g" /etc/network/interfaces
sudo /vagrant/setup_attacker.sh
# /vagrant/remove_ipv6.sh
# sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo cat /etc/netplan/50-vagrant.yaml
sudo netplan apply
# /vagrant/remove_wrong_ipv6_rules
# apt-get update
sudo apt-get install traceroute # quagga quagga-doc traceroute
sudo echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sudo echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

sudo echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.enp0s3.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.enp0s9.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.enp0s10.rp_filter=0" >> /etc/sysctl.conf
sudo echo "net.ipv4.conf.enp0s16.rp_filter=0" >> /etc/sysctl.conf
sudo sysctl -p
sudo apt install net-tools dos2unix -y
sudo cp /vagrant/radvd.conf /etc/radvd.conf
sudo dos2unix /etc/radvd.conf
sudo apt install radvd -y
exit
