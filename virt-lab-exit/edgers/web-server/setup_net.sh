#!/bin/bash
#



apt-get update
apt install net-tools
sudo cp /vagrant/50-vagrant.yaml /etc/netplan/
sudo netplan apply

exit
