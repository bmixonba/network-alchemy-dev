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

The following steps will reproduce the attack.

1. SSH into `attacker`

```bash

$ vagrant ssh attacker

```

2. Establish a VPN connection to the VPN Server

``` bash
$ cd /vagrant

$ sudo openvpn client2.ovpn
```

3. In a second terminal make sure packets are routed to a machine under the attacker's control

```bash

$ sudo ip route add 192.169.3.0/24

```

4. From `attacker`, send packets to the machine

```bash

sudo ./udp_portscan_internal.sh

```

5. SSH to `router1`

```bash
$ vagrant ssh router1
```

6. Send packets from `router1` to `vpnserver` that match `attacker`'s packets from step 4.

```bash
$ sudo ./udp_portscan_external.sh
```

7.  Disconnect `attacker` from the VPN server (Ctrl-c in the terminal from Step 2.)




### Experiments
List each experiment the reviewer has to execute. Describe:
 - How to execute it in detailed steps.
 - What the expected result is.
 - How long it takes and how much space it consumes on disk. (approximately)
 - Which claim and results does it support, and how.

#### Experiment 1: Name
Provide a short explanation of the experiment and expected results.
Describe thoroughly the steps to perform the experiment and to collect and organize the results as expected from your paper.
Use code segments to support the reviewers, e.g.,
```bash
python experiment_1.py
```
#### Experiment 2: Name
...

#### Experiment 3: Name
...

## Limitations

We included only OpenVPN as the VPN target, though our results also include WireGuard and OpenConnect. All of the VPNs we tested (OpenVPN, WireGuard, and OpenConnect), use Netfilter (in the case of Linux based systems), which is what our attacks are actually targeting, OpenVPN was the similast to automate and provision so we focused on it for this artifact. For operating systems, we only included Linux and not FreeBSD. This is because we were unable to find a suitable FreeBSD vagrant box and since our provisioning code uses Vagrant, and since frewer of the attacks actually work on FreeBSD, we focused on Linux.

## Notes on Reusability

Researchers can use the code within this artifact to build additional attacks or testing frameworks against VPN platforms if they wish.
