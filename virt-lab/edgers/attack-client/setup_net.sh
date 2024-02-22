#!/bin/bash
#



apt-get update
apt install net-tools traceroute
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply
# sed -i "s/#VAGRANT-END/up route add -net 192.168.169.0\/16 gw 192.168.169.1 dev enp0s8/g" /etc/network/interfaces
#/etc/init.d/networking restarta


# Setup forwarding
sudo sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g"  /etc/sysctl.conf

echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf

sysctl -p


# TEST THIS AFTER WE DESTROY VAGRANT AGAIN
/vagrant/attacker/setup_attacker.sh
exit
