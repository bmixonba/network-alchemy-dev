#!/bin/bash
#

if ! command -v vagrant &> /dev/null
then
	echo Using alteratate vagrant path
	vagrant=/opt/vagrant
else
	vagrant=vagrant
fi

$vagrant up

echo Copy VPN server generated keys to victim and attacker

cp edgers/vpn-server/client1.ovpn edgers/client/
cp edgers/vpn-server/client2.ovpn edgers/attack-client/

# Need to copy the attacker code to the attack-client shared folder or create a
# sym link or something
read  -n 1 -p "Press enter to exit" mainmenuinput
