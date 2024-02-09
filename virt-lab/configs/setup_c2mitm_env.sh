#!/bin/bash
#

printf "\nConfiguring client attack node..\n\n"

sleep 1



cp -r ~/git/VeepExploit/client-to-mitm/ ~/git/VeepExploit/virt-lab/edgers/attack-client/
cd ../edgers/attack-client/
./copy_attack_client_setup.sh


ssh -p 22169 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./setup_attack_client.sh


cd ../../edgers/web-server
./copy_dns_setup.sh

ssh -p 22113 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./install_docker.sh

#ssh -p 22113 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./start_dns.sh



