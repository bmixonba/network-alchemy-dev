#!/bin/bash
#


echo "Shutting down and deleting all vagrant vms.."

if ! command -v vagrant &> /dev/null
then
	echo Using alteratate vagrant path
	vagrant=/opt/vagrant
else
	vagrant=vagrant
fi

$vagrant halt
