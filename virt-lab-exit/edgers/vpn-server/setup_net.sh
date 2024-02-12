#!/bin/bash
#

apt-get update
apt install net-tools
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

# Need to test this to make sure it works.
/vagrant/vpn_server/setup_vpn.sh

# TODO: Make setup wireguard work.
# /vagrant/vpn_server/setup_wireguard.sh
sudo apt-get install -y conntrack
sudo apt install traceroute -y     
exit
