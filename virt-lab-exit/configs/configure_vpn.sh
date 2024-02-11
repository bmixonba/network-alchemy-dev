#!/bin/bash
#

printf "Configuring vpn server node..\n"
sleep 1


cd ../edgers/vpn-server
./copy_vpn_setup.sh


ssh -p 22119 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost ./setup_vpn.sh 



printf "\n\nConnecting client node to vpn server..\n"
sleep 1

cd ../client
./copy_client_config.sh

#ssh -p 22111 -i .vagrant/machines/default/virtualbox/private_key vagrant@localhost << EOF
#  ./connect.sh
#  exit
#EOF




