#!/bin/bash
#


echo Copying dns setup scripts to dns VM..

scp -r -i .vagrant/machines/default/virtualbox/private_key -P 22113 ../setups/dns/* vagrant@localhost:~


