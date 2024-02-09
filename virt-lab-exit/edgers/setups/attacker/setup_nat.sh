#!/bin/bash
#


echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get install iptables-persistent -y

echo Flusing any old iptables rules..

sudo iptables -F

sudo iptables --table nat -F

sudo iptables --delete-chain

sudo iptables --table nat --delete-chain

echo Adding forward and masquerade rule for NATing

sudo iptables -t nat --append POSTROUTING --out-interface enp0s3 -j MASQUERADE

sudo iptables --append FORWARD --in-interface enp0s8 -j ACCEPT

echo Saving the current iptables config..

sudo netfilter-persistent save


