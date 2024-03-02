#!/bin/bash

rm -f fill_table > /dev/null

make fill_table > /dev/null

/vagrant/client-to-mitm/src/fill_table enp0s8
