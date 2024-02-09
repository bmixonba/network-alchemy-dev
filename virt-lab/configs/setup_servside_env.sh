#!/bin/bash
#

printf "\nConfiguring router1 attacker node..\n\n"

sleep 1


cd ../routers/router1
./copy_attacker_setup.sh


ssh -p 22114 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./setup_attacker.sh


cd ../../edgers/web-server
./copy_dns_setup.sh

ssh -p 22113 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./install_docker.sh

#ssh -p 22113 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./start_dns.sh



