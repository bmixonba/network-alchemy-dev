#!/bin/bash
#


echo Copying vpn setup scripts to vpn VM..


cd ../vpn-server

scp -i .vagrant/machines/default/virtualbox/private_key -P 22119 ../setups/vpn_server/setup* vagrant@localhost:~



