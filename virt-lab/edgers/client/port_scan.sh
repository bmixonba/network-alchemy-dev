#! /bin/bash

 sudo /vagrant/namespaced-openvpn --config /vagrant/client1.ovpn &
 sleep 8
 sudo ip netns exec protected sudo -u $USER -i
 sudo tcpdump -i tun0