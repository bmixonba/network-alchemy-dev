#!/bin/bash
#



apt-get update
apt install net-tools hping3
# /vagrant/remove_ipv6.sh
# sudo ip -6 route flush table all
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply
# /vagrant/remove_wrong_ipv6_rules
exit
