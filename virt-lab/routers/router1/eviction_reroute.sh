#!/bin/bash

#1. Clean the environment
rm -f fill_table > /dev/null
#2. build attack code 
make fill_table > /dev/null

#3. run attack code 
/vagrant/fill_table enp0s8
