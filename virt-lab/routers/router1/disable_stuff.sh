#!/bin/bash
#

echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s3.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s8.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s9.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s10.rp_filter=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.enp0s16.rp_filter=0" >> /etc/sysctl.conf

sysctl -p
