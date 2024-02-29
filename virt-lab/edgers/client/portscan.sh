#!/bin/bash

 sudo /vagrant/namespaced-openvpn --config /vagrant/client1.ovpn --daemon
 sleep 3
 sudo ip netns exec protected sudo -u $USER -i bash << EOF
 sudo tcpdump -i tun0