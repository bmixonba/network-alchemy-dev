#!/bin/bash
#


echo Copying attacker setup scripts to router1 VM..


scp -i .vagrant/machines/default/virtualbox/private_key -P 22117 ../../edgers/setups/attacker/setup_attacker* vagrant@localhost:~



