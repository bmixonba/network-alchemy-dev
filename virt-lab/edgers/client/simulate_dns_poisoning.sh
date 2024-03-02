#!/bin/bash

ADDR=192.168.2.254

sudo echo "${ADDR} foo.com foo.com" >> /etc/hosts
sudo echo "192.168.3.131 bar.com bar.com" >> /etc/hosts
