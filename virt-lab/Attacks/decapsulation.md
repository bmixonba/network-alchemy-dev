# Overview


1. Start the VMs

```bash
$ ./boot_all.sh

```

2. SSH to the Attacker

```bash
$ vagrant ssh attacker
```

3. Connect to the VPN server

```bash

$ cd /vagrant/

$ sudo openvpn client2.ovpn
```

4. Make sure the attacker traffic to the target gets sent through the VPN tunnel.

```bash
$ sudo ip route add 192.168.1.0/24 dev tun0
```

5. Setup the DNAT rule to forward packet to attacker2


```bash
$ sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.254.4
```

6. Run the decapsulation script to create the port shadow on attacker 1.

```bash

$ cd /vagrant/client-to-mitm/src/

$ sudo ./start-decapsulation.sh

```
