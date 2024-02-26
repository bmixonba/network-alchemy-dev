#! /bin/bash

sudo cp /vagrant/radvd.conf /etc/radvd.conf
sudo dos2unix /etc/radvd.conf
sudo systemctl restart radvd
