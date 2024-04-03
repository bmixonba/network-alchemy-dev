#!/bin/bash
#

sudo apt-get update
sudo apt install net-tools hping3 
# /vagrant/remove_ipv6.sh
# sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply
# /vagrant/remove_wrong_ipv6_rules
# Need to test this to make sure it works.
sudo sed -i -e 's/\r$//' /vagrant/vpn_server/setup_vpn.sh
sudo /vagrant/vpn_server/setup_vpn.sh
# /vagrant/vpn_server/setup_v2ray.sh
sudo apt-get install -y conntrack
sudo apt install traceroute -y     
exit
