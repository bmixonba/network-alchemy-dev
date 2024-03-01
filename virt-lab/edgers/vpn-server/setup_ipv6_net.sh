#!/bin/bash
#

apt-get update
apt install net-tools
# /vagrant/remove_ipv6.sh
# sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

# Configure IPv6
# sudo cp /vagrant/ipv6-config/enp0s8.network /etc/systemd/network/enp0s8.network
# sudo systemctl restart systemd-networkd

# /vagrant/remove_wrong_ipv6_rules
# Need to test this to make sure it works.
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

sed -i -e 's/\r$//' /vagrant/vpn_server/setup_vpn.sh
/vagrant/vpn_server/setup_vpn.sh
sudo apt-get install -y conntrack
sudo apt install traceroute -y     
exit
