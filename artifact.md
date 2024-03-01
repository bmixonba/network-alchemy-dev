# Artifact Appendix

Paper title: **Attacking Connection Tracking Frameworks as used by Virtual Private Networks**

Artifacts HotCRP Id: **#161**

Requested Badge: **Reproducible**

## Description
A short description of your artifact and how it links to your paper.

### Security/Privacy Issues and Ethical Concerns

There are not ethical concerns for artifact reviewers or their machines. The primary ethical factors relate to
vulnerability disclosure, which we have already performed. 

## Basic Requirements

### Hardware Requirements: Attack Code

If your artifacts require specific hardware to be executed, mention that here.
Provide instructions on how a reviewer can gain access to that hardware through remote access, buying or renting, or even emulating the hardware.
Make sure to preserve the anonymity of the reviewer at any time.


### Hardware Requirements: Formal Model 

If your artifacts require specific hardware to be executed, mention that here.
Provide instructions on how a reviewer can gain access to that hardware through remote access, buying or renting, or even emulating the hardware.
Make sure to preserve the anonymity of the reviewer at any time.

### Software Requirements: 

#### Attack Code
Describe the OS and software packages required to evaluate your artifact.
This description is essential if you rely on proprietary software or software that might not be easily accessible for other reasons.
Describe how the reviewer can obtain and install all third-party software, data sets, and models.


#### Formal Model
Describe the OS and software packages required to evaluate your artifact.
This description is essential if you rely on proprietary software or software that might not be easily accessible for other reasons.
Describe how the reviewer can obtain and install all third-party software, data sets, and models.

### Estimated Time and Storage Consumption
Provide an estimated value for the time the evaluation will take and the space on the disk it will consume. 
This helps reviewers to schedule the evaluation in their time plan and to see if everything is running as intended.
More specifically, a reviewer, who knows that the evaluation might take 10 hours, does not expect an error if,  after 1 hour, the computer is still calculating things.

## Environment

This artifact contains two components attack code and formal model code.

The attack code is run in a virtual environment that is setup and configured using Vagrant.
The provisioning code has only been tested on a Ubuntu 20.04 operating system.

The formal model code requires the TLA+ toolbox, which can be found [here](https://lamport.azurewebsites.net/tla/toolbox.html) under the `Obtaining the Toolbox` section. The code has only been tested on an Ubuntu 20.04 operating system.

### Accessibility

The artifact can be found at the following github [link](https://github.com/bmixonba/network-alchemy-dev) on the main branch.

```bash
$ git clone https://github.com/bmixonba/network-alchemy-dev.git
```

### Set up the environment

#### Attack Code

The attack code can be run inside a virtual environment generated using the `Vagrantfile` (`virt-lab/Vagrantfile`). Use
the `boot_all.sh` script to build the environment.

```bash
$ git clone https://github.com/bmixonba/network-alchemy-dev.git
$ cd network-alchemy-dev/virt-env/
$ ./boot_all.sh
```

The boot script will generate lots of output related to setup and configuration. Once this 
is complete, you can ssh into the environment. The following example describes how to
ssh into `attacker`.

```bash
$ vagrant ssh attacker
```
There are more detailed instructions for performing the attacks in `virt-lab/README.md`

### Testing the Environment

#### Attack Code
There are four attacks total, `atip`, `decapsulation`, `eviction reroute`, and `port scan`. To ease reproduction, we have provided
detailed instructions for each attack in `virt-lab/README.md`

#### Formal Model

Each attack has an accompanying formal model associated with it in the `Tla` directory.

## Artifact Evaluation

### Main Results and Claims
List all your paper's main results and claims that are supported by your submitted artifacts.

Our paper covers four attacks against VPNs, such as OpenVPN, that use stateful connection tracking. The four attacks are `atip`, `decapsulation`, `eviction reroute`, and `port scan`. We also tested mitigations for these attacks using formal modelling.

#### Main Result 1: ATIP 

##### Attack code

The ATIP attack, described in section 3.1, permits an attacker connected to the VPN server to force a victim's VPN connection request
to be routed to them. When this happens, all the victims packets are routed through the attacker. The results are described in section 4.2.1.

##### Formal Model

The formal model tests mitigations against the ATIP attack.

#### Main Result 2: Decasulation

The decaspsulation attack, described in section 3.2., permits an attacker to redirect a victim's packets to himself unenrypted. The
results are described in section 4.2.4.

#### Main Result 3: Eviction Reroute 

The eviction reroute attack, described in section 3.3, permits an attacker to force replies meant for the victim to himself instead. The results are described in 4.2.5.

#### Main Result 4: Port Scan

The port scan attack, described in section 3.4, permits an attacker to port scan a victim behind the VPN server. The results are described in section 4.2.6.

##### Attack code



### Experiments
List each experiment the reviewer has to execute. Describe:
 - How to execute it in detailed steps.
 - What the expected result is.
 - How long it takes and how much space it consumes on disk. (approximately)
 - Which claim and results does it support, and how.

#### Experiment 1: ATIP
Provide a short explanation of the experiment and expected results.
Describe thoroughly the steps to perform the experiment and to collect and organize the results as expected from your paper.
Use code segments to support the reviewers, e.g.,
```bash
python experiment_1.py
```

To reproduce the ATIP attack, execute the following steps:

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

2. Delete the old `MASQUERADE` rule

```bash

$ /vagrant/delete_insecure_iptables_rule.sh # sudo -D POSTROUTING -s 10.0.0.0/8 -o enp0s8 -j MASQUERADE 

```

3. Add the new `SNAT` rule


```bash

$ /vagrant/mitigate_atip.sh # sudo -A POSTROUTING -s 10.0.0.0/8  -j SNAT --to-source 192.168.2.133

```

4. If you repeat the attack now, it will fail.

##### Formal Model

#### Experiment 2: Decapsulation

##### Attack code

#### Experiment 3: Eviction Reroute 

##### Attack Code

##### Formal Model

#### Experiment 3: Port Scan

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


...

## Limitations

### OpenVPN and Linux Only
We included only OpenVPN as the VPN target, though our results also include WireGuard and OpenConnect. All of the VPNs we tested (OpenVPN, WireGuard, and OpenConnect), use Netfilter (in the case of Linux based systems), which is what our attacks are actually targeting, OpenVPN was the similast to automate and provision so we focused on it for this artifact. For operating systems, we only included Linux and not FreeBSD. This is because we were unable to find a suitable FreeBSD vagrant box and since our provisioning code uses Vagrant, and since frewer of the attacks actually work on FreeBSD, we focused on Linux.

### IPv4 Only

We tested the attacks against both IPv4 and IPv6. We include only IPv4 in this artifact for two reasons. First, because the connection tracking frameworks are shared between IPv4 and IPv6 testing both is redundent. Second, we encountered several issues when configuing IPv6 interfaces and routing that we cannot currently attribute to a cause but that make building the testing environment and code more labor intensive. 

We plan to include WireGuard, OpenConnect, and IPv6 support in future iterations of this framework.


## Notes on Reusability

Researchers can use the code within this artifact to build additional attacks or testing frameworks against VPN platforms if they wish.
