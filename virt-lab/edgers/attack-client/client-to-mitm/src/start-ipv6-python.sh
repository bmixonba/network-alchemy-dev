#!/bin/bash


# sike wrong number of args ---> (public_iface, attacker_pub_ip, victim_ip, vpn_ip, vpn_port, https_port, webdnsserver_ip)
# sudo /vagrant/client-to-mitm/src/full-relay-ipv6 enp0s8 fd12:2345:6789:fe::fe 192.168.1.254 192.168.2.254 1194 80 192.168.3.254

python3 ipv6_relay.py enp0s8 fd12:2345:6789:fe::fe fd12:2345:6789:1::fe fd12:2345:6789:2::fe 1194 80 fd12:2345:6789:3::fe fd00::1001
