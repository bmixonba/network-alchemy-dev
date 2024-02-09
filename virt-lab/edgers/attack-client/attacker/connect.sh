#/bin/bash
#!

echo "Connecting to local vpn server.."

sleep 0.1

sudo openvpn --client --config ../client2.ovpn &


sleep 8 # might need to sleep longer to make sure tun0 exists

echo "Adding ip route rule to force traffic destined for web+dns servers to use vpn tun interface"

sudo ip route add 192.168.3.2 dev tun0
