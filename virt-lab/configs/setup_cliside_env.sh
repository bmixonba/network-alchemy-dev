#!/bin/bash
#


printf "\nConfiguring gateway attacker node..\n\n"

sleep 1


cd ../routers/gateway
./copy_attacker_setup.sh


ssh -p 22117 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./setup_attacker.sh

