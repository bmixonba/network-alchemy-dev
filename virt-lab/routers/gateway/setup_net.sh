#!/bin/bash
#

# OLD_NAME=vague-router
# HNAME=gateway


apt-get update

sed -i "s/#VAGRANT-END/up route add -net 192.168.0.0\/16 gw 192.168.1.254 dev enp0s8/g" /etc/network/interfaces

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

sysctl -p

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get install iptables-persistent -y

echo Flusing any old iptables rules..

sudo iptables -F

sudo iptables --table nat -F

sudo iptables --delete-chain

sudo iptables --table nat --delete-chain

echo Adding forward and masquerade rule for NATing

sudo iptables -t nat --append POSTROUTING --out-interface enp0s8 -j MASQUERADE

sudo iptables --append FORWARD --in-interface enp0s9 -j ACCEPT

echo Saving the current iptables config..

sudo netfilter-persistent save

# sed -i "s/$OLD_NAME/$HNAME/g" /etc/hostname
# sed -i "s/$OLD_NAME/$HNAME/g" /etc/hosts
# hostname $HNAME


exit
