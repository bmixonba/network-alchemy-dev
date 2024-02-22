#!/bin/bash
#

apt-get update
apt install net-tools
/vagrant/remove_ipv6.sh
sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

# Need to test this to make sure it works.
sed -i -e 's/\r$//' /vagrant/vpn_server/setup_vpn.sh
/vagrant/vpn_server/setup_vpn.sh
sudo apt-get install -y conntrack
sudo apt install traceroute -y     
exit
