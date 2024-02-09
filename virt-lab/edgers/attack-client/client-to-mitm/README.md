
# Abstract

An attacker can escalate from a VPN client to a man-in-the-middle (MITM)
between a victim and the VPN server shared between the attacker and the victim.
This is possible because of implementation details Netfilter and how it
performs Network Address Translation (NAT). Once the attacker has positioned
himself as a MITM, he can leverage a recently disclosed, server-side MITM
attack against the victim machine to inject a DNS response into the victims
flows (this claim needs to be verified because the MITM exploit may add
significant delay in a realistic setting).

# Introduction

TODO: Add stuff

# Background

Linux uses a system known as Netfilter for functionality include NAT, stateful
firewall rules, and packet mangling.  Netfilter a combination of a global hash
table `nf_conntrack_hash` to track packet flows birectionally. Entries in this
table represent a connection and contain include information such as the source
and destination of a packet the protocol, including port numbers in the case
of, e.g., UDP and TCP, and flow `status` information such as whether the packet
is _UNREPLIED_, and _ASSURED_. These entries store flow source and destination
as well a reversed version of these IP address for quick lookup, address
translation, routing, and soforth. Because of the way NAT is implemented (i.e.,
through these table entries) and because of the order in which Netfilter hooks
are called, an attacker connected to a NAT can trick the NAT into routing
packets beyond the NAT back to the attacker instead of to the intended
recipient behind the NAT. In the case of VPNs, an attacker can leverage this
behavior as an attack primitives to escalate from a VPN client to a MITM
between the VPN server and a victim whose address the attacker hypothesizes
will connect to the VPN server.

## Attack Methodology

To become a MITM, first assume the victim, V, has not yet connected to the VPN
server.  The attacker, A, first connects to the VPN server as any VPN client
normally would. Next, the attacker sends packets to the victim's IP address. The
source port is set to the VPN server process' listening port. The attacker then
loops through the ephemeral port space to set the destination port to a different 
value on each iteration to cover that space. The attacker does this because the 
victim's source port is selected randomly. The VPN
server performs address translation (NATs) for each packet and routes them on to the victim IP. Each
packet the attacker sends occupies an entry in the `nf_conntrack_hash` table.
Furthermore, each of these entries is in the _UNREPLIED_ state because of our
initial assumption that the victim has not yet connected to the VPN server.
Depending on the protocol (e.g., TCP or UDP) these _UNREPLIED_ entries will
stay in the conntrack table between 30 seconds to two minutes.
Assuming the VPN server uses UDP, these entries remain in the table for at most 30
seconds if they are not garbage collected by Netfilter. Recall that `nf_conn`
entries in the _UNREPLIED_ state are also _not_ assured and may be subject to
early eviction by Netfilter's garbage collector. The attacker can address this
and keep these entries in `nf_conntrack_hash` by sending the same packets every
29 seconds or he can coordinate with external server that spoofs responses to
the these packets to VPN server. In the latter case, the entries will
trasnition from _UNREPLIED_ to _REPLIED_, will be in the _ASSURED_ state, and
hence inelgible for early eviction by Netfilter's garbage collector.

Once the VPN server's `nf_conntrack_hash` table is primed as previously
described, the attacker listens for packets with the victim's IP address as the
source address. Now, when `V` attempts to connect to `VPN`, `VPN` routes `V`
request to `A` based on the translation from the `nf_conn` entry in
`nf_conntrack_hash`. `A` observes this packet because the destination port is
whatever `VPN` is listening on. All `A` needs to do at this point is act as a NAT
itself and repackage this response with it's own, public IP address, and send it
to `VPN`. `VPN` simply interprets this as another VPN connection request and
replies with the appriorate response back to `A`'s public IP address.
`A` repackages this packet and sends it back to the victim. `A` is now a MITM.

# Directory Contents

- README.md: This file
- src: Directory containing source code
- src/simple-relay.cpp: a basic version of the attack that assumes we already know the client's source port. For demonstration purposes.
- src/full-relay.cpp: The full version of the attack that fills the ephemeral port space.
- src/dns-reroute.cpp: Attack that reroutes an adjacent VPN client's DNS requests to the attacker.
- src/txid-bruteforce.cpp: Used to find the txid of a victim's DNS TXIDs when doing a server-side attack.
- src/full_udp_ports.cpp: Used to fill the target's UDP port space when performing the DNS reroute attack.
- src/Makefile: Make file that can be used to make any the above attack PoCs.
- src/<ANYTHING ELSE > I'll have to go back over the rest when I have more time or as questions arise.

# Attacks
## C2MITM
This coude uses the full relay
# tldr; 

1. Attacker connects to VPN server. Force all traffic from attacker to client to go through the VPN tunnel
```bash
attacker$ sudo openvpn --config /vagrant/client2.ovpn &
attacker$ sudo ip route add 192.168.1.254 dev tun0
```
where `192.168.1.254` is the public IP of the victim

2. Attacker starts VPN relay

```bash
attacker$ cd /vagrant/client-to-mitm/src
attacker$ ./start-full-attack.sh
```

4. Victim attempts to connect to VPN server

```bash
victim$ sudo openvpn --config /vagrant/client1.ovpn
```

5. Attacker is now in-path between VPN server and victim. You can verify this by collecting a packet capture
and/or watching the relay's standard output.

# TODO:
* It would be nice for a reviewer/user of this code if the pcap was generated automatically
* Make the relay write the output to a log file for review, processing, and comparision.
* The above tasks require orchestration. Implement autotmation using an orchestration system like ansible, chef, or whatever the current thing is. 

## Deanontmization

1. TODO: Write this. The verification was done on pcaps and somewhat manually and I cannot find the python code originally used for that. Could have been in a VM I nuked.

1. Automate this stuff. 

## Eviction Reroute (Dns reroute)

1. TODO: Write this it's been a while. 

## Port forward overwrite. Not in here explictly. Mostly manual verification using nping.

