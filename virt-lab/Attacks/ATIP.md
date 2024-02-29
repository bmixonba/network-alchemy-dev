# Overview
This are the steps to perform the Adjacent-to-in-path attack.

1. Start the VMs

```bash
$ ./boot_all.sh
```

2. SSH to the Attacker and victim

```bash
$ vagrant ssh attacker
$ vagrant ssh victim
```
### Attacker
3. Connect to the VPN server

```bash
$ cd /vagrant/
$ sudo openvpn client2.ovpn
```

4. Make sure the attacker traffic to the target gets sent through the VPN tunnel.

```bash
$ sudo ip route add 192.168.1.0/24 dev tun0
```

5. Start the port shadow and listen for victim


```bash
$ cd /vagrant/client-to-mitm/src/
$ sudo ./start-full-attack.sh
```
### Victim
6. Run the decapsulation script to create the port shadow.

```bash
$ cd /vagrant/
$ sudo openvpn client1.ovpn
```
The attacker should now be in path between the victim and the server.