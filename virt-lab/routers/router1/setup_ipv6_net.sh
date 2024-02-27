#!/bin/bash
#

apt-get update

sed -i "s/#VAGRANT-END/up route add -net 192.168.0.0\/16 gw 192.168.1.254 dev enp0s8/g" /etc/network/interfaces
# /vagrant/remove_ipv6.sh
# sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.ipv6.yaml /etc/netplan/
cat /etc/netplan/50-vagrant.ipv6.yaml
sudo netplan apply

# Configure IPv6
sudo cp /vagrant/ipv6-config/enp0s8.network /etc/systemd/network/
sudo systemctl restart systemd-networkd
# /vagrant/remove_wrong_ipv6_rules
# apt-get update
apt-get install traceroute # quagga quagga-doc traceroute
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s3.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s9.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s10.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s16.rp_filter=0" >> /etc/sysctl.conf
sysctl -p
sudo apt install net-tools dos2unix -y
sudo cp /vagrant/radvd.conf /etc/radvd.conf
sudo dos2unix /etc/radvd.conf
sudo apt install radvd -y
exit
