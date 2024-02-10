#!/bin/bash


# sike wrong number of args ---> (public_iface, attacker_pub_ip, victim_ip, vpn_ip, vpn_port, https_port, webdnsserver_ip)
sudo /vagrant/client-to-mitm/src/full-relay enp0s8 192.168.254.254 192.168.1.254 192.168.2.254 1194 80 192.168.3.254
