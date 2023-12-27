--------------------------- MODULE conntrackVuln ---------------------------

EXTENDS Naturals, TLC, Sequences, FiniteSets
\* Modification History
\* Last modified Tue Feb 07 18:01:31 MST 2023 by conntrack
\* Last modified Mon Feb 06 23:33:18 UTC 2023 by ben
\* Created Tue Oct 11 10:53:30 MDT 2022 by conntrack
(* --algorithm conntrackVuln {

variables
A = "A",
B = "B",
C = "C",
D = "D",
N = "N",
NN = "NN",
Aa="a", 
Bb="b",
Cc="c",
Dd="d",
Ee="e",
Ff="f",
Gg="g",
Hh="h",
Ii="i",
Jj="j",
Kk="k",
Ll="l",
Mm="m",
Nn="n", 
Oo="o",
Pp="p",
Qq="q", 
Rr="r", 
Ss="s", 
Tt="t",
Uu="u",
Vv="v",
Ww="w", 
Xx="x",
Yy="y",
Zz="z",
H1 = 1,
H2 = 2,

MaxPorts=1,
EP1 = "N1",
PortMap1 = <<>>,
EP2 = "N2",
PortMap2 = <<>>,
TableFull=FALSE,
EvictionReroute=FALSE,
PortScanInv=FALSE,
MaxTableSize=2,
hosts = <<H1, H2, C>>;
FreeHosts = <<H1, H2>>,

UsedHosts = <<>>,
Ports = <<A, B, C, NN>>,
ExtraPorts = <<D>>;
ExtraExtraPorts = <<Aa, Bb, Cc, Dd,Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz>>;
T = <<>>,
FreeIPs = <<A, B>>,
UsedIPs = <<>>,
Connections = <<>>,
SendQueue = <<>>,
RcvQueue = <<>>,
MAX = 3,
Marker1 = H1,
Marker2 = H2;
CmdConnect = "Connect";
CmdDisconnect = "Disconnect";
PortSpaceFull = FALSE; 

(* BEGIN: vulnerable versions *)

procedure ConnectVuln(depth)
  variables host, hidx, host_idx, pidx, port_idx
{
  connectVEvtSeqV: call EventSequenceVuln(depth);
  connectVStart:
  if ( Len(FreeHosts) > 0 ) {
      print <<"ConnectVuln:", FreeHosts, FreeHosts>>;
      host_idx := DOMAIN FreeHosts;
      hidx := CHOOSE h \in host_idx : TRUE;
      host := FreeHosts[hidx];
      (*
      FreeIPs := SelectSeq(FreeIPs, LAMBDA e: ~(e=ip));
      UsedIPs := Append(UsedIPs, ip);
      *)
      FreeHosts := SelectSeq(FreeHosts, LAMBDA a: a /= host);
      UsedHosts := Append(UsedHosts, host);
      ip_idx := DOMAIN FreeIPs;
      ipidx := CHOOSE ipp \in ip_idx : TRUE;
      ip := FreeIPs[ipidx];
      FreeIPs := SelectSeq(FreeIPs, LAMBDA d: d /= ip);
      UsedIPs := Append(UsedIPs, ip);
      Connections := Append(Connections, <<ip, host>>);
      (* SendQueue := Append(SendQueue, pkt); *)
  };
  connectVRet: return;
}

procedure DisconnectVuln(depth)
variables ip, host, connDomain, cidx, conn
{
  disconnectVEvtSV: call EventSequenceVuln(depth);
  disconnectVStart: 
  if ( Len(Connections) > 0) {
    connDomain := DOMAIN Connections;
    cidx := CHOOSE c \in connDomain : TRUE;
    conn := Connections[cidx];
    ip := conn[1];
    host := conn[2];

    print << "Disconnect- Before:", host, ip, Connections>>;
    Connections := SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip);
    UsedIPs := SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip);
    FreeIPs := Append(FreeIPs, ip);
    
    FreeHosts := Append(FreeHosts, host);
    UsedHosts := SelectSeq(UsedHosts, LAMBDA m: m /= host);
    
    print << "Disconnect- After: ", host, ip, Connections>>;
  };
  disconnectRet: return ;
}

(*Manually connect instead of randomly selecting one of the IPs.*)
procedure ConnectMan(host, ip)
  variables hidx, host_idx, pidx, port_idx
{
  connectManStart:
  if ( Len(FreeHosts) > 0 ) {
      print << "ConnectMan - BEFORE ", FreeHosts, FreeIPs, Connections>>;

      (* *)FreeIPs := SelectSeq(FreeIPs, LAMBDA e: ~(e=ip));
      UsedIPs := Append(UsedIPs, ip); 
      FreeHosts := SelectSeq(FreeHosts, LAMBDA a: a /= host);
      UsedHosts := Append(UsedHosts, host);
      (*  *)  Connections := Append(Connections,  <<ip, host>>);
      print << "ConnectMan - AFTER ", FreeHosts, FreeIPs, Connections>>;
      port_idx := DOMAIN Ports;
      pidx := CHOOSE p \in port_idx : TRUE;
  };
  connectManRet: return;
}

procedure DisconnectMan(host, ip)
variables connDomain, cidx, conn
{
  disconnectManStart: 

  if ( Len(Connections) > 0) {
    print << "DisconnectMan - Before:", host, ip, Connections>>;
    Connections := SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip);
    UsedIPs := SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip);
    FreeIPs := Append(FreeIPs, ip);
    FreeHosts := Append(FreeHosts, host);
    UsedHosts := SelectSeq(UsedHosts, LAMBDA m: m /= host);
    print << "DisconnectMan - After: ", host, ip, Connections>>;
    (* Remove translations for host that disconnected. *)
    disconnectVulnPurgeOrphans1: T := SelectSeq(T, LAMBDA e: e.orig.saddr /= ip);
    disconnectVulnPurgeOrphans2: T := SelectSeq(T, LAMBDA e: e.orig.saddr /= host);    
    if (host=H1) {
        PortMap1 := <<>>;
    } else {
        PortMap2 := <<>>;
    };

    
  };
  disconnectManRet: return ;
}

procedure DisconnectVulnMan(host, ip)
variables connDomain, cidx, conn
{
  disconnectVulnManStart: 

  if ( Len(Connections) > 0) {

    print << "DisconnectVulnMan- Before:", host, ip, Connections>>;     
    Connections := SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip);
    UsedIPs := SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip);
    FreeIPs := Append(FreeIPs, ip);
    FreeHosts := Append(FreeHosts, host);
    UsedHosts := SelectSeq(UsedHosts, LAMBDA m: m /= host);
    print << "DisconnectVulnMan - After: ", host, ip, Connections>>;
    (* Remove translations for host that disconnected. *)    
  };
  disconnectVulnManRet: return ;
}


procedure Evict() {
  evictStart:
  print "Evict";
  if (Len(T) > 0) {
    T := Tail(T);
  };
  evictRet: return;
}

procedure PubToPrivVuln(depth)
variables pkt, ipkt, entry, conn, hostMarker, ip_idx, ipidx, ip, host
{
  pubtoprivVEvt3: call EventSequenceVuln(depth);
  pubtoprivVStart:
  if (Len(SendQueue) > 0) {
    pkt := Head(SendQueue);
    print <<"PubToPrivMan - Len(SendQueue) > 0:", pkt, Connections, T>>;
    SendQueue := Tail(SendQueue);
    if (Len(T) > 0) {
      print <<"PubToPrivMan - Len(T) > 0:">>;
      entry := SelectSeq(T, LAMBDA e: e.reply.saddr=pkt.saddr /\ 
                                      e.reply.sport=pkt.sport /\
                                      e.reply.daddr=pkt.daddr /\
                                      e.reply.dport=pkt.dport);
      if (entry=defaultInitValue) {
        pubtirprivVDE: return ;
      };
      pubtoprivEEmpty:
      if (Len(entry) <= 0) {
         print <<"PubToPrivVuln - Empty Entry">>
         (* assert(FALSE); We can just let this slide since it's OK in real networks.*)
      } else {
        print <<"PubToPrivMan - Len(entry) > -0:", entry, pkt>>;
        (* There is a matching translation/routing rule. *)
        pubtoPrivElse: entry := Head(entry);
        if (entry.reply.dport=N) {
          print <<"PubToPrivMan - PortShadow: ", entry, pkt>>;
        };
        if ( entry.host_marker/=pkt.host_marker ) {
          print <<"PubToPrivMan - entry.host_marker/=pkt.host_marker:", entry, pkt>>;
          (* 
          EvictionReroute and Request Diversion:
 
          The case when the host creates a private host creates an entry and a different host sends a packet
          to the intermediary is not always error in at least two cases, when the host expects 
          a response and its entry is evicted and replaced by anothe private host and when the port
          is a listening port. Otherwise, this looks like NAT traverseral or P2P traffic.
          
          Error because of a bad eviction. The host who generated the packet
          is different from the host receiving the packet. *)
          if (pkt.host_marker = H1) {
            Marker1 := entry.host_marker;
          } else {
            Marker2 := entry.host_marker;
          };
          print <<"PubToPrivMan-Eviction Error: pkt", pkt, " entry", entry, "Connections:", Connections, "T: ", T>>;              
          (* assert(entry.host_marker= pkt.host_marker); *)
        };
        conn := SelectSeq(Connections, LAMBDA e: entry.orig.saddr = Head(e));
        if (Len(conn) > 0) {
          pubtoprivVConngt1: conn := Head(conn);
          pubtoprivVConngt2: hostMarker := conn[2];
          (* PortScanning: Error because of a switched private host host.
          print <<"PubToPriv - Address Management Error: hostMarker", hostMarker, " entry: ", entry, "conn", conn, "pkt", pkt>>;
          print <<"Marker1", Marker1, "Marker2", Marker2>>;*)
          if ( hostMarker = H1 ) {
            if (entry.host_marker = H2) {
              PortScanInv := TRUE;
            };
            Marker1 := entry.host_marker;
          } else {
            if (entry.host_marker = H1) {
              PortScanInv := TRUE;
            };       
            Marker2 := entry.host_marker;
          };
          (* print <<"PubToPriv - Address Management Error: hostMarker", hostMarker, " entry: ", entry, "conn", conn, "pkt", pkt>>;
          print <<"Marker1", Marker1, "Marker2", Marker2>>;
          HostMarkers[hostMarker] := entry.host_marker;              
          assert( hostMarker = entry.host_marker);*)
        };        
      };
    };
  };
  pubtopriVvRet: return ;
}

procedure PubToPrivMan()
variables pkt, ipkt, entry, conn, hostMarker, ip_idx, ipidx, ip, host
{
  pubtoprivManStart:
  if (Len(SendQueue) > 0) {
    pkt := Head(SendQueue);
    print <<"PubToPrivMan - Len(SendQueue) > 0:", pkt, Connections, T>>;
    SendQueue := Tail(SendQueue);
    if (Len(T) > 0) {
      print <<"PubToPrivMan - Len(T) > 0:">>;
      entry := SelectSeq(T, LAMBDA e: e.reply.saddr=pkt.saddr /\ 
                                      e.reply.sport=pkt.sport /\
                                      e.reply.daddr=pkt.daddr /\
                                      e.reply.dport=pkt.dport);
      if (Len(entry) <= 0) {
        assert(FALSE); (*We can just let this slide since it's OK in real networks.*)
      } else {
        print <<"PubToPrivMan - Len(entry) > -0:", entry, pkt>>;
        (* There is a matching translation/routing rule. *)
        pubtoPrivElse: entry := Head(entry);
        if (entry.reply.dport=N) {
          print <<"PubToPrivMan - PortShadow: ", entry, pkt>>;
        };
        if ( entry.host_marker/=pkt.host_marker ) {
          print <<"PubToPrivMan - entry.host_marker/=pkt.host_marker:", entry, pkt>>;
          (* EvictionReroute:
          Error because of a bad eviction. The host who generated the packet
          is different from the host receiving the packet. *)
          if (pkt.host_marker = H1) {
             Marker1 := entry.host_marker;
             if (entry.host_marker = H2) {
               EvictionReroute := TRUE;
             };
          } else {
             Marker2 := entry.host_marker;
             if (entry.host_marker = H1) {
               EvictionReroute := TRUE;
             };
          };
          print <<"PubToPrivMan - Eviction Error: pkt", pkt, " entry", entry, "Connections:", Connections, "T: ", T>>;
          (* assert(entry.host_marker= pkt.host_marker); *)
        };
        conn := SelectSeq(Connections, LAMBDA e: entry.orig.saddr = Head(e));
        if (Len(conn) > 0) {
          pubtoprivConngt1: conn := Head(conn);
          pubtoprivConngt2: hostMarker := conn[2];
          (*Error because of a switched host.
          print <<"PubToPriv - Address Management Error: hostMarker", hostMarker, " entry: ", entry, "conn", conn, "pkt", pkt>>;
          print <<"Marker1", Marker1, "Marker2", Marker2>>;*)
          if ( hostMarker = H1 ) {
            if (entry.host_marker = H2) {
              PortScanInv := TRUE;
            };
            Marker1 := entry.host_marker;
          } else {
            if (entry.host_marker = H1) {
              PortScanInv := TRUE;
            };       
            Marker2 := entry.host_marker;
          };
          (* print <<"PubToPriv - Address Management Error: hostMarker", hostMarker, " entry: ", entry, "conn", conn, "pkt", pkt>>;
          print <<"Marker1", Marker1, "Marker2", Marker2>>;
          HostMarkers[hostMarker] := entry.host_marker;              
          assert( hostMarker = entry.host_marker);*)
        };        
      };
    };
  } else {
    print <<"PubToPrivMan - Else Len(SendQueue) <= 0">>;
  };
  pubtoprivRet: return ;
}

procedure PrivToPubMan2(conn, sport, dstAddr, dport) 
 variables pkt, hostMarker, daddr, hostidx, hidx,
 otherEntry, i, indicies, portDomain, sourcePort, destPort, new_sport
{
  privtopubManStart:
  if (Len (Connections) > 0) {
    sourcePort := sport; (* Ports[sourcePort]; *)
    privtopubMan2Dport: destPort := dport; (* Ports[destPort]; *)
    daddr := dstAddr; (*hosts[hidx]; *)
    (* *)print <<"PrivToPub - Conn: ", conn>>; 
    hostMarker := Head(Tail(conn));
    pkt := [saddr |-> Head(conn), sport |-> sourcePort, (*XXX: Might need to change this to make sure the old attacks work*)
            daddr |-> daddr, dport |-> destPort,
            host_marker |-> hostMarker
           ];
    print <<"PrivToPubMan - pkt: ", conn, pkt>>;
           
    entry := [host_marker |-> hostMarker,
              orig |-> [saddr |-> pkt.saddr, sport |-> pkt.sport,
                        daddr |-> pkt.daddr, dport |-> pkt.dport],
              reply |-> [saddr |-> pkt.daddr, sport |-> pkt.dport, 
                         daddr |-> N,  dport |-> pkt.sport ]]; (*Doesn't account for selecting a new packet*)

    otherEntry := SelectSeq(T, LAMBDA k: k.reply.saddr=pkt.daddr /\ k.reply.sport=pkt.dport /\
                                         k.reply.daddr=N /\ k.reply.dport=pkt.sport);
    (* *)print <<"PrivToPub - T", T, otherEntry, pkt>>; 
    if ( Len(otherEntry) > 0) {
          T := SelectSeq(T, LAMBDA e: ~(e.reply.saddr=pkt.daddr /\ e.reply.sport=pkt.dport /\
                                        e.reply.daddr=N /\ e.reply.dport=pkt.sport) );
    };
    privtoPubMan2AddT: T := Append(T, entry);
    privtopubPkt: pkt := [saddr |->pkt.daddr, sport |-> pkt.dport,
                          daddr |-> N, dport |-> pkt.sport,
                          host_marker |-> hostMarker];
    SendQueue := Append(SendQueue, pkt);
  };
  privtopubMan2Ret: return;
}

procedure PrivToPubVuln(depth)
 variables pkt, conn, hostMarker, daddr, hostidx, hidx,
 otherEntry, i, indicies, portDomain, sourcePort, destPort, new_sport
{
  privtopubV3: call EventSequenceVuln(depth);
  privtopubManStart:
  if (Len (Connections) > 0) {
    indicies := DOMAIN Connections;
    portDomain := DOMAIN Ports;
    sourcePort := CHOOSE pr \in portDomain : TRUE;
    i := CHOOSE f \in indicies : TRUE;
    (* *)print <<"PrivToPub - conn", indecies, conn, Connections>>; 
    privtopubConn: conn := Connections[i];
    sourcePort := Ports[sourcePort];
    portDomain := DOMAIN Ports;
    destPort := CHOOSE h \in portDomain : TRUE;
    privtopubDport: destPort := Ports[destPort];
    hostidx := DOMAIN hosts;
    hidx := CHOOSE hid \in hostidx : TRUE;
    daddr := hosts[hidx];
    (* *) print <<"PrivToPubVuln - Conn: ", conn>>; 
    hostMarker := Head(Tail(conn));

    pkt := [saddr |-> Head(conn), sport |-> sourcePort, (*XXX: Might need to change this to make sure the old attacks work*)
            daddr |-> daddr, dport |-> destPort,
            host_marker |-> hostMarker
           ];
    print <<"PrivToPubMan - pkt: ", conn, pkt>>;
           
    entry := [host_marker |-> hostMarker,
              orig |-> [saddr |-> pkt.saddr, sport |-> pkt.sport,
                        daddr |-> pkt.daddr, dport |-> pkt.dport],
              reply |-> [saddr |-> pkt.daddr, sport |-> pkt.dport, 
                         daddr |-> N,  dport |-> pkt.sport ]]; (*Doesn't account for selecting a new packet*)

    otherEntry := SelectSeq(T, LAMBDA k: k.reply.saddr=pkt.daddr /\ k.reply.sport=pkt.dport /\
                                         k.reply.daddr=N /\ k.reply.dport=pkt.sport /\ k.host_marker /= hostMarker);
    (* *)print <<"PrivToPub - T", T, otherEntry, pkt>>; 
    if ( Len(otherEntry) > 0) {
          T := SelectSeq(T, LAMBDA e: ~(e.reply.saddr=pkt.daddr /\ e.reply.sport=pkt.dport /\
                                        e.reply.daddr=N /\ e.reply.dport=pkt.sport) );
    };
    privtoPubManAddT: T := Append(T, entry);
      if ( Len(T) > MaxTableSize ) {
          TableFull := TRUE;
      };
    
    privtopubPkt: pkt := [saddr |->pkt.daddr, sport |-> pkt.dport,
                          daddr |-> N, dport |-> pkt.sport,
                          host_marker |-> hostMarker];
    SendQueue := Append(SendQueue, pkt);
  };
  privtopubRet: return;
}


procedure PrivToPubMan() 
 variables pkt, conn, hostMarker, daddr, hostidx, hidx,
 otherEntry, i, indicies, portDomain, sourcePort, destPort, new_sport
{
  privtopubManStart:
  if (Len (Connections) > 0) {
    indicies := DOMAIN Connections;
    portDomain := DOMAIN Ports;
    sourcePort := CHOOSE pr \in portDomain : TRUE;
    i := CHOOSE f \in indicies : TRUE;
    privtopubManConn: conn := Connections[i];
    sourcePort := B; (* Ports[sourcePort]; *)
    portDomain := DOMAIN Ports;
    (* *) destPort := CHOOSE h \in portDomain : TRUE; 
    privtopubManDport: destPort := C; (* Ports[destPort]; *)
    hostidx := DOMAIN hosts;
    hidx := CHOOSE hid \in hostidx : TRUE;
    daddr := C; (*hosts[hidx]; *)
    (* *)print <<"PrivToPubMan - Len(connections) > 0: ", indicies, conn, Connections>>; 
    hostMarker := Head(Tail(conn));
    pkt := [saddr |-> Head(conn), sport |-> sourcePort, (*XXX: Might need to change this to make sure the old attacks work*)
            daddr |-> daddr, dport |-> destPort,
            host_marker |-> hostMarker
           ];
    print <<"PrivToPubMan - conn, pkt: ", conn, pkt>>;
           
    entry := [host_marker |-> hostMarker,
              orig |-> [saddr |-> pkt.saddr, sport |-> pkt.sport,
                        daddr |-> pkt.daddr, dport |-> pkt.dport],
              reply |-> [saddr |-> pkt.daddr, sport |-> pkt.dport, 
                         daddr |-> N,  dport |-> pkt.sport ]]; (*Doesn't account for selecting a new packet*)

    otherEntry := SelectSeq(T, LAMBDA k: k.reply.saddr=pkt.daddr /\ k.reply.sport=pkt.dport /\
                                         k.reply.daddr=N /\ k.reply.dport=pkt.sport);
    (* *)print <<"PrivToPubMan - T", T, otherEntry, pkt>>; 
    if ( Len(otherEntry) > 0) {
          T := SelectSeq(T, LAMBDA e: ~(e.reply.saddr=pkt.daddr /\ e.reply.sport=pkt.dport /\
                                        e.reply.daddr=N /\ e.reply.dport=pkt.sport) );
    };
    privtoPubManAddT: T := Append(T, entry);
    privtopubPkt: pkt := [saddr |->pkt.daddr, sport |-> pkt.dport,
                          daddr |-> N, dport |-> pkt.sport,
                          host_marker |-> hostMarker];
    SendQueue := Append(SendQueue, pkt);
  };
  privtopubRet: return;
}
(*END: vulnerable versions *)

(*BEGIN: fixed version*)
procedure Connect(depth)
  variables host, hidx, host_idx, pidx, port_idx
{
  connectStart: call EventSequence(depth);
  connectIf: if ( Len(FreeHosts) > 0 ) {
      host_idx := DOMAIN FreeHosts;
      hidx := CHOOSE h \in host_idx : TRUE;
      host := FreeHosts[hidx];
      (* print << "Connect - BEFORE ", host, FreeHosts, UsedHosts, Connections>>;
      FreeIPs := SelectSeq(FreeIPs, LAMBDA e: ~(e=ip));
      UsedIPs := Append(UsedIPs, ip); *)
      FreeHosts := SelectSeq(FreeHosts, LAMBDA a: a /= host);
      UsedHosts := Append(UsedHosts, host);
      (* print << "Connect - BEFORE ", host, FreeHosts, UsedHosts, Connections>>;
      Connections := Append(Connections,  <<ip, host>>); *)
      port_idx := DOMAIN Ports;
      pidx := CHOOSE p \in port_idx : TRUE;
      (* The vulnerable version selects an I Pfrom the FreeIPs list, the fixed version does not. Why? Because we are statically assigning an IP to each host and this is this is equivalent to doing that.  *)
      pkt := [ saddr |-> host, sport |-> Ports[pidx],
               daddr |-> N,    dport |-> N,
               cmd |-> CmdConnect,
               host_marker |-> host];

      SendQueue := Append(SendQueue, pkt); 
  };
  connectRet: return;
}

procedure Disconnect(depth)
variables ip, host, connDomain, cidx, conn
{
  disconnectStart: call EventSequence(depth);
  disconnectIf: 
  if ( Len(Connections) > 0) {
    connDomain := DOMAIN Connections;
    cidx := CHOOSE c \in connDomain : TRUE;
    conn := Connections[cidx];
    ip := conn[1];
    host := conn[2];

    print << "Disconnect- Before:", host, ip, Connections>>;
    Connections := SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip);
    UsedIPs := SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip);
    FreeIPs := Append(FreeIPs, ip);
     
    (* Remove translations for host that disconnected. *)
    disconnectPurgeOrphans1: T := SelectSeq(T, LAMBDA e: e.orig.saddr /= ip);
    disconnectPurgeOrphans2: T := SelectSeq(T, LAMBDA e: e.orig.saddr /= host);    
    if (host=H1) {
        PortMap1 := <<>>;
    } else {
        PortMap2 := <<>>;
    };
    FreeHosts := Append(FreeHosts, host);
    UsedHosts := SelectSeq(UsedHosts, LAMBDA m: m /= host);
    print << "Disconnect- After: ", host, ip, Connections>>;
  };
  disconnectRet: return ;
}

procedure PubToPriv(depth)
variables pkt, ipkt, entry, conn, hostMarker, ip_idx, ipidx, ip, host
{
  pubtoprivStart: call EventSequence(depth);

  pubtoprivIf: if (Len(SendQueue) > 0) {
    (*
    1. Select a packet from the send queue
    2. Find the entries mapping, if it exists.
    3. Check that the packets host marker and the table entry's host marker are the same.
    4.  If they are, route it else this is an error
    *)
    pkt := Head(SendQueue);
    print <<"PubToPriv", pkt, Connections>>;
    (* print <<"PubToPriv", pkt, SendQueue>>; *)
    SendQueue := Tail(SendQueue);
    entry := SelectSeq(T, LAMBDA e: e.reply.saddr=pkt.saddr /\ 
                                    e.reply.sport=pkt.sport /\
                                    e.reply.daddr=pkt.daddr /\
                                    e.reply.dport=pkt.dport);
    (* print <<"PubToPriv", pkt, entry>>; *)
    (* If there isn't a translation, it's meant for us. *)
    if (Len(entry) <= 0) {
      if (pkt.dport = N ) {
        (*Connect to a listening port. *)
        if (Len(FreeIPs) > 0) {
          ip_idx := DOMAIN FreeIPs;
          ipidx := CHOOSE ipp \in ip_idx : TRUE;
          ip := FreeIPs[ipidx];
          FreeIPs := SelectSeq(FreeIPs, LAMBDA d: d /= ip);
          UsedIPs := Append(UsedIPs, ip);
          host := pkt.saddr;
          Connections := Append(Connections, <<ip, host>>);
        } (*else {
          assert(TRUE);
        }*);
      } else if ( pkt.dport = NN ) {
        (* XXX: Get the packet back to the private realm hosts
        or DO a check *)
        assert(TRUE);
      } else {
        (*XXX: This is when the destination port is not anything.
          In theory, this would lead to an ICMP or something.
        *)
        assert(TRUE);
      };
    } else {
      (* There is a matching translation/routing rule. *)
      pubtoPrivElse: entry := Head(entry);
      
      if (entry.reply.dport=N) {
        print <<"PubToPriv - PortShadow: ", entry, pkt>>;
      };
      if ( entry.host_marker/=pkt.host_marker ) {
        (* EvictionReroute:
              
        Error because of a bad eviction. The host who generated the packet
        is different from the host receiving the packet. *)
        if (pkt.host_marker = H1) {
           Marker1 := entry.host_marker;
           if (entry.host_marker = H2) {
             EvictionReroute := TRUE;
           };
        } else {
           Marker2 := entry.host_marker;        
           if (entry.host_marker = H1) {
             EvictionReroute := TRUE;
           };
        };
        print <<"PubToPriv-Eviction Error: pkt", pkt, " entry", entry, "Connections:", Connections, "T: ", T>>;              
          (* assert(entry.host_marker= pkt.host_marker); *)
      };
      (* PortScan:
          
      Insecure because the incoming packets host_marker doesn't match 
      the host associated with the incoming packet*)
          
      conn := SelectSeq(Connections, LAMBDA e: entry.orig.saddr = Head(e));
      if (Len(conn) > 0) {
        pubtoprivConngt1: conn := Head(conn);
        pubtoprivConngt2: hostMarker := conn[2];
        (*Error because of a switched host.
        print <<"PubToPriv - Address Management Error: hostMarker", hostMarker, " entry: ", entry, "conn", conn, "pkt", pkt>>;
        print <<"Marker1", Marker1, "Marker2", Marker2>>;*)
        if ( hostMarker = H1 ) {
          if (entry.host_marker = H2) {
            PortScanInv := TRUE;
          };
          Marker1 := entry.host_marker;
        } else {
          if (entry.host_marker = H1) {
            PortScanInv := TRUE;
          };       
          Marker2 := entry.host_marker;
        };
        (* print <<"PubToPriv - Address Management Error: hostMarker", hostMarker, " entry: ", entry, "conn", conn, "pkt", pkt>>;
        print <<"Marker1", Marker1, "Marker2", Marker2>>;
        HostMarkers[hostMarker] := entry.host_marker;              
        assert( hostMarker = entry.host_marker);*)
      };
    };
  };
  pubtoprivRet: return ;
}

procedure PrivToPub(depth) 
 variables pkt, conn, hostMarker, daddr, hostidx, hidx, otherEntry, i, indicies, portDomain, sourcePort, destPort, new_sport, good
{
  privtopubStart: call EventSequence(depth);
  privtopubIf: 
  good:=TRUE;
  if (Len (Connections) > 0) {
    indicies := DOMAIN Connections;
    portDomain := DOMAIN Ports;
    sourcePort := CHOOSE pr \in portDomain : TRUE;
    i := CHOOSE f \in indicies : TRUE;
    (* print <<"PrivToPub - conn", indecies, conn, Connections>>; *)
    privtopubConn: conn := Connections[i];
    sourcePort := Ports[sourcePort];
    portDomain := DOMAIN Ports;
    destPort := CHOOSE h \in portDomain : TRUE;
    privtopubDport: destPort := Ports[destPort];
    hostidx := DOMAIN hosts;
    hidx := CHOOSE hid \in hostidx : TRUE;
    daddr := hosts[hidx];
    (* print <<"PrivToPub - Conn: ", conn>>; *)
    hostMarker := Head(Tail(conn));

    if (hostMarker=H1) {
      if (Len(PortMap1) >= MaxPorts) {
          good := FALSE;
          privtopubMaxPorts1: return;
      } else {
        PortMap1 := Append(PortMap1, sourcePort);
      }
    } else {
      if (Len(PortMap2) >= MaxPorts) {
          good := FALSE;
          privtopubMaxPorts2: return;
      } else {
         PortMap2 := Append(PortMap2, sourcePort);
      }
    };
    privtopubGood: if ( good ) {
      privToPubPkt1:
      if (sourcePort = N) {
          if ( hostMarker=H1 ) {
            sourcePort := EP1;
          } else {
            sourcePort := EP2;            
          };
      };
      pkt := [saddr |-> Head(conn), sport |-> sourcePort, (*XXX: Might need to change this to make sure the old attacks work*)
              daddr |-> daddr, dport |-> destPort,
              host_marker |-> hostMarker
             ];
      print <<"PrivToPub - pkt: ", conn, pkt>>;

      entry := [host_marker |-> hostMarker,
                orig |-> [saddr |-> pkt.saddr, sport |-> pkt.sport,
                          daddr |-> pkt.daddr, dport |-> pkt.dport],
                reply |-> [saddr |-> pkt.daddr, sport |-> pkt.dport,
                           daddr |-> N,  dport |-> pkt.sport ]]; (*Doesn't account for selecting a new packet*)

      otherEntry := SelectSeq(T, LAMBDA k: k.reply.saddr=pkt.daddr /\ k.reply.sport=pkt.dport /\
                                           k.reply.daddr=N /\ k.reply.dport=pkt.sport /\
                                           k.hostMarker /= hostMarker);
      (* print <<"PrivToPub - T", T, otherEntry, pkt>>; *)
      if ( Len(otherEntry) > 0) {
          (* Should we force the eviction? Do it for now.*)
          print "Evict";
          if (Len(ExtraPorts) > 0) {
            new_sport := Head(ExtraPorts);
            ExtraPorts := Tail(ExtraPorts);
            privToPubNewPort: entry := [host_marker |-> hostMarker,
                      orig |-> [saddr |-> pkt.saddr, sport |-> pkt.sport,
                                daddr |-> pkt.daddr, dport |-> pkt.dport],
                      reply |-> [saddr |-> pkt.daddr, sport |-> pkt.dport, 
                                 daddr |-> N,  dport |-> new_sport ]]; (*Doesn't account for selecting a new packet*)
          
            (* T := SelectSeq(T, LAMBDA e: ~(e.reply.saddr=pkt.daddr /\ e.reply.sport=pkt.dport /\
                                        e.reply.daddr=N /\ e.reply.dport=pkt.sport) );*)
            pkt.sport := new_sport;
          } else {
            PortSpaceFull := TRUE;
            (*
            new_sport := Head(ExtraExtraPorts);
            ExtraExtraPorts := Tail(ExtraExtraPorts);          
            privToPubNewPort2: entry := [host_marker |-> hostMarker,
                      orig |-> [saddr |-> pkt.saddr, sport |-> pkt.sport,
                                daddr |-> pkt.daddr, dport |-> pkt.dport],
                      reply |-> [saddr |-> pkt.daddr, sport |-> pkt.dport, 
                                 daddr |-> N,  dport |-> new_sport ]]; (*Doesn't account for selecting a new packet*)
            *)
          };
          (* print <<"PrivToPub - Evicting from T", T, otherEntry>>; *)        
      };
      (* print <<"PrivToPub - T", T, otherEntry>>; *)
      privToPubAppendT: T:= Append(T, entry);
      if ( Len(T) >= MaxTableSize ) {
          TableFull := TRUE;
      };
      (* print <<"PrivToPub - T", T>>; *)
      privtopubPkt: pkt := [saddr |->pkt.daddr, sport |-> pkt.dport,
                            daddr |-> N, dport |-> pkt.sport,
                            host_marker |-> hostMarker];
      SendQueue := Append(SendQueue, pkt);
    };
  };
  privtopubRet: return;
}
(*END: fixed version*)

procedure OldPortScan() {
  portscan1: call ConnectMan(1, B);
  portscan11: print <<"SendQueue:", SendQueue, T>>;
  portscan2: call PrivToPubMan();
  portscan21: print <<"SendQueue:", SendQueue, T>>;  
  portscan3: call DisconnectVulnMan(1, B);
  portscan31: print <<"SendQueue:", SendQueue, T>>;  
  portscan4: call ConnectMan(2, B);
  portscan41: print <<"SendQueue:", SendQueue, T>>;  
  portscan5: call PubToPrivMan();
  portscan51: print <<"SendQueue:", SendQueue, T>>;    
  return ;
}

(*

procedure EvictReroute() {
  evictReroute1: call ConnectMan(1, B);
  evictReroute11: print <<"SendQueue:", SendQueue>>;
  evictReroute2: call PrivToPubMan2(<<B, 1>>, B, C, C);
  evictReroute12: print <<"SendQueue:", SendQueue>>;
  evictReroute3: call ConnectMan(2, A);
  evictReroute13: print <<"SendQueue:", SendQueue>>;
  evictReroute4: call PrivToPubMan2(<<A, 2>>,A, C, C);
  evictReroute14: print <<"SendQueue:", SendQueue>>;
  evictReroute5: call PrivToPubMan2(<<A, 2>>,C,  C, C);
  evictReroute15: print <<"SendQueue:", SendQueue>>;
  evictReroute6: call PrivToPubMan2(<<A, 2>>, B, C, C);
  evictReroute16: print <<"SendQueue:", SendQueue>>;
  evictReroute7: call PubToPrivMan();
  evictReroute17: print <<"SendQueue:", SendQueue>>;
  evictReroute8: call PubToPrivMan();
  evictReroute18: print <<"SendQueue:", SendQueue>>;
  evictReroute9: call PubToPrivMan();
  evictReroute19: print <<"SendQueue:", SendQueue>>;
  evictReroute10: call PubToPrivMan();
  evictReroute110: print <<"SendQueue:", SendQueue>>;
  return ;
}
*)

procedure EventSequenceVuln(depth)
variables i, j, ip, host, indecies
{
        (* print <<"EventSequence - depth=", i>>; *)
      evtSeqVStart:
      if (depth <= 0) {
        return ;
      } else {
        either {
          if ( Len(FreeIPs) > 0) {
            (* eventSeqConnIf1: indecies := DOMAIN FreeIPs;
            eventSeqConnIf2 :j := CHOOSE a \in indecies : TRUE;
            print <<"EventSequence - j = ", j>>; *)
            print <<"EventSequenceVuln - depth = ", depth>>;
            call ConnectVuln(depth - 1);
          };
        } or {
            if (Len (Connections) > 0) {
                (* eventSeqDiscIf1: indecies := DOMAIN Connections;
                eventSeqDiscIf2: j := CHOOSE a \in indecies : TRUE;
                conn := Connections[j]; *)
                print <<"EventSequenceVuln - Disconnect", Connections>>;
                call DisconnectVuln(depth - 1);
            };
        } or {
          if (Len(Connections) > 0) {
              print <<"EventSequenceVuln - PrivToPubVuln:", Connections>>;
              call PrivToPubVuln(depth - 1);
          };
        } or {
           if (Len(SendQueue) > 0) {
               print <<"EventSequenceVuln - PubToPrivVuln: depth - ", depth, SendQueue>>;           
               call PubToPrivVuln(depth - 1);
           };
        };
    };
  evtSeqVRet: return ;
};

procedure EventSequence(depth)
variables i, j, ip, host, indecies
{
     evtSeqStart:
     if (depth <= 0) { 
       evtSeqD0: return ;
     } else {
        (* print <<"EventSequence - depth=", i>>; *)
        either {
          if ( Len(FreeIPs) > 0) {
            (* eventSeqConnIf1: indecies := DOMAIN FreeIPs;
            eventSeqConnIf2 :j := CHOOSE a \in indecies : TRUE;
            print <<"EventSequence - j = ", j>>; *)
            call Connect(depth - 1);
          };
        } or {
            if (Len (Connections) > 0) {
                (* eventSeqDiscIf1: indecies := DOMAIN Connections;
                print <<"EventSequence - FreeIPs", Connections>>;
                eventSeqDiscIf2: j := CHOOSE a \in indecies : TRUE;
                conn := Connections[j]; *)
                call Disconnect(depth - 1);
            };
        } or {
          if (Len(Connections) > 0) {
              call PrivToPub(depth - 1);
          };
        } or {
           if (Len(SendQueue) > 0) {
               call PubToPriv(depth - 1);
           };
        };
    };

  evtSeqRet: return ;
};

procedure CheckModel() 
variables i
{
   
   checkModelStart: 
   i := 0;   
   checkModelWhile: while ( i < MAX) {
     call EventSequence(MAX);
     checkModelInc: i := i + 1; 
   };
   checkModelRet: return;
}

procedure CheckModelVuln() 
variables i
{
   
   checkModelVulnStart: 
   i := 0;   
   checkModelVulnWhile: while ( i < MAX) {
     call EventSequenceVuln(MAX);
     checkModelVulnInc: i := i + 1; 
   };
   checkModelVulnRet: return;
}

procedure PortScan() {
  portscan1: call Connect(0);
  portscan2: call PrivToPub(0);
  portscan3: call Disconnect(0);
  portscan4: call Connect(0);
  portscan5: call PubToPriv(0);
  return ;
}


process (Foo="A") 
variables aa
{
  foo1:
  (* aa := [saddr : {1}, sport : {1, 2},
         daddr : {3, 4}, dport : {5, 6}]; *)
  print "Test";
  
  (* Works again *)
  (* print aa; call OldPortScan(); *) 
  (* Works again *)
  (* call EvictReroute(); *)
  (*   *)
  call CheckModel();

}

} *)
\* BEGIN TRANSLATION (chksum(pcal) = "9558cf36" /\ chksum(tla) = "9d554561")
\* Label disconnectRet of procedure DisconnectVuln at line 127 col 18 changed to disconnectRet_
\* Label pubtoPrivElse of procedure PubToPrivVuln at line 230 col 24 changed to pubtoPrivElse_
\* Label pubtoPrivElse of procedure PubToPrivMan at line 302 col 24 changed to pubtoPrivElse_P
\* Label pubtoprivConngt1 of procedure PubToPrivMan at line 327 col 29 changed to pubtoprivConngt1_
\* Label pubtoprivConngt2 of procedure PubToPrivMan at line 328 col 29 changed to pubtoprivConngt2_
\* Label pubtoprivRet of procedure PubToPrivMan at line 353 col 17 changed to pubtoprivRet_
\* Label privtopubManStart of procedure PrivToPubMan2 at line 361 col 3 changed to privtopubManStart_
\* Label privtopubPkt of procedure PrivToPubMan2 at line 387 col 19 changed to privtopubPkt_
\* Label privtopubManStart of procedure PrivToPubVuln at line 401 col 3 changed to privtopubManStart_P
\* Label privtopubConn of procedure PrivToPubVuln at line 407 col 20 changed to privtopubConn_
\* Label privtopubDport of procedure PrivToPubVuln at line 411 col 21 changed to privtopubDport_
\* Label privtoPubManAddT of procedure PrivToPubVuln at line 437 col 23 changed to privtoPubManAddT_
\* Label privtopubPkt of procedure PrivToPubVuln at line 442 col 19 changed to privtopubPkt_P
\* Label privtopubRet of procedure PrivToPubVuln at line 447 col 17 changed to privtopubRet_
\* Label privtopubPkt of procedure PrivToPubMan at line 491 col 19 changed to privtopubPkt_Pr
\* Label privtopubRet of procedure PrivToPubMan at line 496 col 17 changed to privtopubRet_P
\* Label portscan1 of procedure OldPortScan at line 775 col 14 changed to portscan1_
\* Label portscan2 of procedure OldPortScan at line 777 col 14 changed to portscan2_
\* Label portscan3 of procedure OldPortScan at line 779 col 14 changed to portscan3_
\* Label portscan4 of procedure OldPortScan at line 781 col 14 changed to portscan4_
\* Label portscan5 of procedure OldPortScan at line 783 col 14 changed to portscan5_
\* Procedure variable host of procedure ConnectVuln at line 78 col 13 changed to host_
\* Procedure variable hidx of procedure ConnectVuln at line 78 col 19 changed to hidx_
\* Procedure variable host_idx of procedure ConnectVuln at line 78 col 25 changed to host_idx_
\* Procedure variable pidx of procedure ConnectVuln at line 78 col 35 changed to pidx_
\* Procedure variable port_idx of procedure ConnectVuln at line 78 col 41 changed to port_idx_
\* Procedure variable ip of procedure DisconnectVuln at line 105 col 11 changed to ip_
\* Procedure variable host of procedure DisconnectVuln at line 105 col 15 changed to host_D
\* Procedure variable connDomain of procedure DisconnectVuln at line 105 col 21 changed to connDomain_
\* Procedure variable cidx of procedure DisconnectVuln at line 105 col 33 changed to cidx_
\* Procedure variable conn of procedure DisconnectVuln at line 105 col 39 changed to conn_
\* Procedure variable hidx of procedure ConnectMan at line 131 col 13 changed to hidx_C
\* Procedure variable host_idx of procedure ConnectMan at line 131 col 19 changed to host_idx_C
\* Procedure variable pidx of procedure ConnectMan at line 131 col 29 changed to pidx_C
\* Procedure variable port_idx of procedure ConnectMan at line 131 col 35 changed to port_idx_C
\* Procedure variable connDomain of procedure DisconnectMan at line 150 col 11 changed to connDomain_D
\* Procedure variable cidx of procedure DisconnectMan at line 150 col 23 changed to cidx_D
\* Procedure variable conn of procedure DisconnectMan at line 150 col 29 changed to conn_D
\* Procedure variable connDomain of procedure DisconnectVulnMan at line 177 col 11 changed to connDomain_Di
\* Procedure variable cidx of procedure DisconnectVulnMan at line 177 col 23 changed to cidx_Di
\* Procedure variable conn of procedure DisconnectVulnMan at line 177 col 29 changed to conn_Di
\* Procedure variable pkt of procedure PubToPrivVuln at line 206 col 11 changed to pkt_
\* Procedure variable ipkt of procedure PubToPrivVuln at line 206 col 16 changed to ipkt_
\* Procedure variable entry of procedure PubToPrivVuln at line 206 col 22 changed to entry_
\* Procedure variable conn of procedure PubToPrivVuln at line 206 col 29 changed to conn_P
\* Procedure variable hostMarker of procedure PubToPrivVuln at line 206 col 35 changed to hostMarker_
\* Procedure variable ip_idx of procedure PubToPrivVuln at line 206 col 47 changed to ip_idx_
\* Procedure variable ipidx of procedure PubToPrivVuln at line 206 col 55 changed to ipidx_
\* Procedure variable ip of procedure PubToPrivVuln at line 206 col 62 changed to ip_P
\* Procedure variable host of procedure PubToPrivVuln at line 206 col 66 changed to host_P
\* Procedure variable pkt of procedure PubToPrivMan at line 284 col 11 changed to pkt_P
\* Procedure variable ipkt of procedure PubToPrivMan at line 284 col 16 changed to ipkt_P
\* Procedure variable entry of procedure PubToPrivMan at line 284 col 22 changed to entry_P
\* Procedure variable conn of procedure PubToPrivMan at line 284 col 29 changed to conn_Pu
\* Procedure variable hostMarker of procedure PubToPrivMan at line 284 col 35 changed to hostMarker_P
\* Procedure variable ip_idx of procedure PubToPrivMan at line 284 col 47 changed to ip_idx_P
\* Procedure variable ipidx of procedure PubToPrivMan at line 284 col 55 changed to ipidx_P
\* Procedure variable ip of procedure PubToPrivMan at line 284 col 62 changed to ip_Pu
\* Procedure variable host of procedure PubToPrivMan at line 284 col 66 changed to host_Pu
\* Procedure variable pkt of procedure PrivToPubMan2 at line 357 col 12 changed to pkt_Pr
\* Procedure variable hostMarker of procedure PrivToPubMan2 at line 357 col 17 changed to hostMarker_Pr
\* Procedure variable daddr of procedure PrivToPubMan2 at line 357 col 29 changed to daddr_
\* Procedure variable hostidx of procedure PrivToPubMan2 at line 357 col 36 changed to hostidx_
\* Procedure variable hidx of procedure PrivToPubMan2 at line 357 col 45 changed to hidx_P
\* Procedure variable otherEntry of procedure PrivToPubMan2 at line 358 col 2 changed to otherEntry_
\* Procedure variable i of procedure PrivToPubMan2 at line 358 col 14 changed to i_
\* Procedure variable indicies of procedure PrivToPubMan2 at line 358 col 17 changed to indicies_
\* Procedure variable portDomain of procedure PrivToPubMan2 at line 358 col 27 changed to portDomain_
\* Procedure variable sourcePort of procedure PrivToPubMan2 at line 358 col 39 changed to sourcePort_
\* Procedure variable destPort of procedure PrivToPubMan2 at line 358 col 51 changed to destPort_
\* Procedure variable new_sport of procedure PrivToPubMan2 at line 358 col 61 changed to new_sport_
\* Procedure variable pkt of procedure PrivToPubVuln at line 396 col 12 changed to pkt_Pri
\* Procedure variable conn of procedure PrivToPubVuln at line 396 col 17 changed to conn_Pr
\* Procedure variable hostMarker of procedure PrivToPubVuln at line 396 col 23 changed to hostMarker_Pri
\* Procedure variable daddr of procedure PrivToPubVuln at line 396 col 35 changed to daddr_P
\* Procedure variable hostidx of procedure PrivToPubVuln at line 396 col 42 changed to hostidx_P
\* Procedure variable hidx of procedure PrivToPubVuln at line 396 col 51 changed to hidx_Pr
\* Procedure variable otherEntry of procedure PrivToPubVuln at line 397 col 2 changed to otherEntry_P
\* Procedure variable i of procedure PrivToPubVuln at line 397 col 14 changed to i_P
\* Procedure variable indicies of procedure PrivToPubVuln at line 397 col 17 changed to indicies_P
\* Procedure variable portDomain of procedure PrivToPubVuln at line 397 col 27 changed to portDomain_P
\* Procedure variable sourcePort of procedure PrivToPubVuln at line 397 col 39 changed to sourcePort_P
\* Procedure variable destPort of procedure PrivToPubVuln at line 397 col 51 changed to destPort_P
\* Procedure variable new_sport of procedure PrivToPubVuln at line 397 col 61 changed to new_sport_P
\* Procedure variable pkt of procedure PrivToPubMan at line 452 col 12 changed to pkt_Priv
\* Procedure variable conn of procedure PrivToPubMan at line 452 col 17 changed to conn_Pri
\* Procedure variable hostMarker of procedure PrivToPubMan at line 452 col 23 changed to hostMarker_Priv
\* Procedure variable daddr of procedure PrivToPubMan at line 452 col 35 changed to daddr_Pr
\* Procedure variable hostidx of procedure PrivToPubMan at line 452 col 42 changed to hostidx_Pr
\* Procedure variable hidx of procedure PrivToPubMan at line 452 col 51 changed to hidx_Pri
\* Procedure variable otherEntry of procedure PrivToPubMan at line 453 col 2 changed to otherEntry_Pr
\* Procedure variable i of procedure PrivToPubMan at line 453 col 14 changed to i_Pr
\* Procedure variable indicies of procedure PrivToPubMan at line 453 col 17 changed to indicies_Pr
\* Procedure variable portDomain of procedure PrivToPubMan at line 453 col 27 changed to portDomain_Pr
\* Procedure variable sourcePort of procedure PrivToPubMan at line 453 col 39 changed to sourcePort_Pr
\* Procedure variable destPort of procedure PrivToPubMan at line 453 col 51 changed to destPort_Pr
\* Procedure variable new_sport of procedure PrivToPubMan at line 453 col 61 changed to new_sport_Pr
\* Procedure variable host of procedure Connect at line 502 col 13 changed to host_C
\* Procedure variable hidx of procedure Connect at line 502 col 19 changed to hidx_Co
\* Procedure variable ip of procedure Disconnect at line 529 col 11 changed to ip_D
\* Procedure variable host of procedure Disconnect at line 529 col 15 changed to host_Di
\* Procedure variable conn of procedure Disconnect at line 529 col 39 changed to conn_Dis
\* Procedure variable pkt of procedure PubToPriv at line 562 col 11 changed to pkt_Pu
\* Procedure variable conn of procedure PubToPriv at line 562 col 29 changed to conn_Pub
\* Procedure variable hostMarker of procedure PubToPriv at line 562 col 35 changed to hostMarker_Pu
\* Procedure variable ip of procedure PubToPriv at line 562 col 62 changed to ip_Pub
\* Procedure variable host of procedure PubToPriv at line 562 col 66 changed to host_Pub
\* Procedure variable conn of procedure PrivToPub at line 667 col 17 changed to conn_Priv
\* Procedure variable i of procedure PrivToPub at line 667 col 69 changed to i_Pri
\* Procedure variable i of procedure EventSequenceVuln at line 816 col 11 changed to i_E
\* Procedure variable j of procedure EventSequenceVuln at line 816 col 14 changed to j_
\* Procedure variable ip of procedure EventSequenceVuln at line 816 col 17 changed to ip_E
\* Procedure variable host of procedure EventSequenceVuln at line 816 col 21 changed to host_E
\* Procedure variable indecies of procedure EventSequenceVuln at line 816 col 27 changed to indecies_
\* Procedure variable i of procedure EventSequence at line 855 col 11 changed to i_Ev
\* Procedure variable ip of procedure EventSequence at line 855 col 17 changed to ip_Ev
\* Procedure variable host of procedure EventSequence at line 855 col 21 changed to host_Ev
\* Procedure variable i of procedure CheckModel at line 892 col 11 changed to i_C
\* Parameter depth of procedure ConnectVuln at line 77 col 23 changed to depth_
\* Parameter depth of procedure DisconnectVuln at line 104 col 26 changed to depth_D
\* Parameter host of procedure ConnectMan at line 130 col 22 changed to host_Co
\* Parameter ip of procedure ConnectMan at line 130 col 28 changed to ip_C
\* Parameter host of procedure DisconnectMan at line 149 col 25 changed to host_Dis
\* Parameter ip of procedure DisconnectMan at line 149 col 31 changed to ip_Di
\* Parameter depth of procedure PubToPrivVuln at line 205 col 25 changed to depth_P
\* Parameter depth of procedure PrivToPubVuln at line 395 col 25 changed to depth_Pr
\* Parameter depth of procedure Connect at line 501 col 19 changed to depth_C
\* Parameter depth of procedure Disconnect at line 528 col 22 changed to depth_Di
\* Parameter depth of procedure PubToPriv at line 561 col 21 changed to depth_Pu
\* Parameter depth of procedure PrivToPub at line 666 col 21 changed to depth_Pri
\* Parameter depth of procedure EventSequenceVuln at line 815 col 29 changed to depth_E
CONSTANT defaultInitValue
VARIABLES A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, 
          Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
          MaxPorts, EP1, PortMap1, EP2, PortMap2, TableFull, EvictionReroute, 
          PortScanInv, MaxTableSize, hosts, FreeHosts, UsedHosts, Ports, 
          ExtraPorts, ExtraExtraPorts, T, FreeIPs, UsedIPs, Connections, 
          SendQueue, RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
          CmdDisconnect, PortSpaceFull, pc, stack, depth_, host_, hidx_, 
          host_idx_, pidx_, port_idx_, depth_D, ip_, host_D, connDomain_, 
          cidx_, conn_, host_Co, ip_C, hidx_C, host_idx_C, pidx_C, port_idx_C, 
          host_Dis, ip_Di, connDomain_D, cidx_D, conn_D, host, ip, 
          connDomain_Di, cidx_Di, conn_Di, depth_P, pkt_, ipkt_, entry_, 
          conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
          entry_P, conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
          conn, sport, dstAddr, dport, pkt_Pr, hostMarker_Pr, daddr_, 
          hostidx_, hidx_P, otherEntry_, i_, indicies_, portDomain_, 
          sourcePort_, destPort_, new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
          hostMarker_Pri, daddr_P, hostidx_P, hidx_Pr, otherEntry_P, i_P, 
          indicies_P, portDomain_P, sourcePort_P, destPort_P, new_sport_P, 
          pkt_Priv, conn_Pri, hostMarker_Priv, daddr_Pr, hostidx_Pr, hidx_Pri, 
          otherEntry_Pr, i_Pr, indicies_Pr, portDomain_Pr, sourcePort_Pr, 
          destPort_Pr, new_sport_Pr, depth_C, host_C, hidx_Co, host_idx, pidx, 
          port_idx, depth_Di, ip_D, host_Di, connDomain, cidx, conn_Dis, 
          depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, hostMarker_Pu, ip_idx, 
          ipidx, ip_Pub, host_Pub, depth_Pri, pkt, conn_Priv, hostMarker, 
          daddr, hostidx, hidx, otherEntry, i_Pri, indicies, portDomain, 
          sourcePort, destPort, new_sport, good, depth_E, i_E, j_, ip_E, 
          host_E, indecies_, depth, i_Ev, j, ip_Ev, host_Ev, indecies, i_C, i, 
          aa

vars == << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, 
           Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
           MaxPorts, EP1, PortMap1, EP2, PortMap2, TableFull, EvictionReroute, 
           PortScanInv, MaxTableSize, hosts, FreeHosts, UsedHosts, Ports, 
           ExtraPorts, ExtraExtraPorts, T, FreeIPs, UsedIPs, Connections, 
           SendQueue, RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
           CmdDisconnect, PortSpaceFull, pc, stack, depth_, host_, hidx_, 
           host_idx_, pidx_, port_idx_, depth_D, ip_, host_D, connDomain_, 
           cidx_, conn_, host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
           port_idx_C, host_Dis, ip_Di, connDomain_D, cidx_D, conn_D, host, 
           ip, connDomain_Di, cidx_Di, conn_Di, depth_P, pkt_, ipkt_, entry_, 
           conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
           entry_P, conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
           conn, sport, dstAddr, dport, pkt_Pr, hostMarker_Pr, daddr_, 
           hostidx_, hidx_P, otherEntry_, i_, indicies_, portDomain_, 
           sourcePort_, destPort_, new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
           hostMarker_Pri, daddr_P, hostidx_P, hidx_Pr, otherEntry_P, i_P, 
           indicies_P, portDomain_P, sourcePort_P, destPort_P, new_sport_P, 
           pkt_Priv, conn_Pri, hostMarker_Priv, daddr_Pr, hostidx_Pr, 
           hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, portDomain_Pr, 
           sourcePort_Pr, destPort_Pr, new_sport_Pr, depth_C, host_C, hidx_Co, 
           host_idx, pidx, port_idx, depth_Di, ip_D, host_Di, connDomain, 
           cidx, conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
           hostMarker_Pu, ip_idx, ipidx, ip_Pub, host_Pub, depth_Pri, pkt, 
           conn_Priv, hostMarker, daddr, hostidx, hidx, otherEntry, i_Pri, 
           indicies, portDomain, sourcePort, destPort, new_sport, good, 
           depth_E, i_E, j_, ip_E, host_E, indecies_, depth, i_Ev, j, ip_Ev, 
           host_Ev, indecies, i_C, i, aa >>

ProcSet == {"A"}

Init == (* Global variables *)
        /\ A = "A"
        /\ B = "B"
        /\ C = "C"
        /\ D = "D"
        /\ N = "N"
        /\ NN = "NN"
        /\ Aa = "a"
        /\ Bb = "b"
        /\ Cc = "c"
        /\ Dd = "d"
        /\ Ee = "e"
        /\ Ff = "f"
        /\ Gg = "g"
        /\ Hh = "h"
        /\ Ii = "i"
        /\ Jj = "j"
        /\ Kk = "k"
        /\ Ll = "l"
        /\ Mm = "m"
        /\ Nn = "n"
        /\ Oo = "o"
        /\ Pp = "p"
        /\ Qq = "q"
        /\ Rr = "r"
        /\ Ss = "s"
        /\ Tt = "t"
        /\ Uu = "u"
        /\ Vv = "v"
        /\ Ww = "w"
        /\ Xx = "x"
        /\ Yy = "y"
        /\ Zz = "z"
        /\ H1 = 1
        /\ H2 = 2
        /\ MaxPorts = 1
        /\ EP1 = "N1"
        /\ PortMap1 = <<>>
        /\ EP2 = "N2"
        /\ PortMap2 = <<>>
        /\ TableFull = FALSE
        /\ EvictionReroute = FALSE
        /\ PortScanInv = FALSE
        /\ MaxTableSize = 2
        /\ hosts = <<H1, H2, C>>
        /\ FreeHosts = <<H1, H2>>
        /\ UsedHosts = <<>>
        /\ Ports = <<A, B, C, NN>>
        /\ ExtraPorts = <<D>>
        /\ ExtraExtraPorts = <<Aa, Bb, Cc, Dd,Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz>>
        /\ T = <<>>
        /\ FreeIPs = <<A, B>>
        /\ UsedIPs = <<>>
        /\ Connections = <<>>
        /\ SendQueue = <<>>
        /\ RcvQueue = <<>>
        /\ MAX = 3
        /\ Marker1 = H1
        /\ Marker2 = H2
        /\ CmdConnect = "Connect"
        /\ CmdDisconnect = "Disconnect"
        /\ PortSpaceFull = FALSE
        (* Procedure ConnectVuln *)
        /\ depth_ = [ self \in ProcSet |-> defaultInitValue]
        /\ host_ = [ self \in ProcSet |-> defaultInitValue]
        /\ hidx_ = [ self \in ProcSet |-> defaultInitValue]
        /\ host_idx_ = [ self \in ProcSet |-> defaultInitValue]
        /\ pidx_ = [ self \in ProcSet |-> defaultInitValue]
        /\ port_idx_ = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure DisconnectVuln *)
        /\ depth_D = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_ = [ self \in ProcSet |-> defaultInitValue]
        /\ host_D = [ self \in ProcSet |-> defaultInitValue]
        /\ connDomain_ = [ self \in ProcSet |-> defaultInitValue]
        /\ cidx_ = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_ = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure ConnectMan *)
        /\ host_Co = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_C = [ self \in ProcSet |-> defaultInitValue]
        /\ hidx_C = [ self \in ProcSet |-> defaultInitValue]
        /\ host_idx_C = [ self \in ProcSet |-> defaultInitValue]
        /\ pidx_C = [ self \in ProcSet |-> defaultInitValue]
        /\ port_idx_C = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure DisconnectMan *)
        /\ host_Dis = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_Di = [ self \in ProcSet |-> defaultInitValue]
        /\ connDomain_D = [ self \in ProcSet |-> defaultInitValue]
        /\ cidx_D = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_D = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure DisconnectVulnMan *)
        /\ host = [ self \in ProcSet |-> defaultInitValue]
        /\ ip = [ self \in ProcSet |-> defaultInitValue]
        /\ connDomain_Di = [ self \in ProcSet |-> defaultInitValue]
        /\ cidx_Di = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_Di = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure PubToPrivVuln *)
        /\ depth_P = [ self \in ProcSet |-> defaultInitValue]
        /\ pkt_ = [ self \in ProcSet |-> defaultInitValue]
        /\ ipkt_ = [ self \in ProcSet |-> defaultInitValue]
        /\ entry_ = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_P = [ self \in ProcSet |-> defaultInitValue]
        /\ hostMarker_ = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_idx_ = [ self \in ProcSet |-> defaultInitValue]
        /\ ipidx_ = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_P = [ self \in ProcSet |-> defaultInitValue]
        /\ host_P = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure PubToPrivMan *)
        /\ pkt_P = [ self \in ProcSet |-> defaultInitValue]
        /\ ipkt_P = [ self \in ProcSet |-> defaultInitValue]
        /\ entry_P = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_Pu = [ self \in ProcSet |-> defaultInitValue]
        /\ hostMarker_P = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_idx_P = [ self \in ProcSet |-> defaultInitValue]
        /\ ipidx_P = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_Pu = [ self \in ProcSet |-> defaultInitValue]
        /\ host_Pu = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure PrivToPubMan2 *)
        /\ conn = [ self \in ProcSet |-> defaultInitValue]
        /\ sport = [ self \in ProcSet |-> defaultInitValue]
        /\ dstAddr = [ self \in ProcSet |-> defaultInitValue]
        /\ dport = [ self \in ProcSet |-> defaultInitValue]
        /\ pkt_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ hostMarker_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ daddr_ = [ self \in ProcSet |-> defaultInitValue]
        /\ hostidx_ = [ self \in ProcSet |-> defaultInitValue]
        /\ hidx_P = [ self \in ProcSet |-> defaultInitValue]
        /\ otherEntry_ = [ self \in ProcSet |-> defaultInitValue]
        /\ i_ = [ self \in ProcSet |-> defaultInitValue]
        /\ indicies_ = [ self \in ProcSet |-> defaultInitValue]
        /\ portDomain_ = [ self \in ProcSet |-> defaultInitValue]
        /\ sourcePort_ = [ self \in ProcSet |-> defaultInitValue]
        /\ destPort_ = [ self \in ProcSet |-> defaultInitValue]
        /\ new_sport_ = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure PrivToPubVuln *)
        /\ depth_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ pkt_Pri = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ hostMarker_Pri = [ self \in ProcSet |-> defaultInitValue]
        /\ daddr_P = [ self \in ProcSet |-> defaultInitValue]
        /\ hostidx_P = [ self \in ProcSet |-> defaultInitValue]
        /\ hidx_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ otherEntry_P = [ self \in ProcSet |-> defaultInitValue]
        /\ i_P = [ self \in ProcSet |-> defaultInitValue]
        /\ indicies_P = [ self \in ProcSet |-> defaultInitValue]
        /\ portDomain_P = [ self \in ProcSet |-> defaultInitValue]
        /\ sourcePort_P = [ self \in ProcSet |-> defaultInitValue]
        /\ destPort_P = [ self \in ProcSet |-> defaultInitValue]
        /\ new_sport_P = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure PrivToPubMan *)
        /\ pkt_Priv = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_Pri = [ self \in ProcSet |-> defaultInitValue]
        /\ hostMarker_Priv = [ self \in ProcSet |-> defaultInitValue]
        /\ daddr_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ hostidx_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ hidx_Pri = [ self \in ProcSet |-> defaultInitValue]
        /\ otherEntry_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ i_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ indicies_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ portDomain_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ sourcePort_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ destPort_Pr = [ self \in ProcSet |-> defaultInitValue]
        /\ new_sport_Pr = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure Connect *)
        /\ depth_C = [ self \in ProcSet |-> defaultInitValue]
        /\ host_C = [ self \in ProcSet |-> defaultInitValue]
        /\ hidx_Co = [ self \in ProcSet |-> defaultInitValue]
        /\ host_idx = [ self \in ProcSet |-> defaultInitValue]
        /\ pidx = [ self \in ProcSet |-> defaultInitValue]
        /\ port_idx = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure Disconnect *)
        /\ depth_Di = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_D = [ self \in ProcSet |-> defaultInitValue]
        /\ host_Di = [ self \in ProcSet |-> defaultInitValue]
        /\ connDomain = [ self \in ProcSet |-> defaultInitValue]
        /\ cidx = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_Dis = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure PubToPriv *)
        /\ depth_Pu = [ self \in ProcSet |-> defaultInitValue]
        /\ pkt_Pu = [ self \in ProcSet |-> defaultInitValue]
        /\ ipkt = [ self \in ProcSet |-> defaultInitValue]
        /\ entry = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_Pub = [ self \in ProcSet |-> defaultInitValue]
        /\ hostMarker_Pu = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_idx = [ self \in ProcSet |-> defaultInitValue]
        /\ ipidx = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_Pub = [ self \in ProcSet |-> defaultInitValue]
        /\ host_Pub = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure PrivToPub *)
        /\ depth_Pri = [ self \in ProcSet |-> defaultInitValue]
        /\ pkt = [ self \in ProcSet |-> defaultInitValue]
        /\ conn_Priv = [ self \in ProcSet |-> defaultInitValue]
        /\ hostMarker = [ self \in ProcSet |-> defaultInitValue]
        /\ daddr = [ self \in ProcSet |-> defaultInitValue]
        /\ hostidx = [ self \in ProcSet |-> defaultInitValue]
        /\ hidx = [ self \in ProcSet |-> defaultInitValue]
        /\ otherEntry = [ self \in ProcSet |-> defaultInitValue]
        /\ i_Pri = [ self \in ProcSet |-> defaultInitValue]
        /\ indicies = [ self \in ProcSet |-> defaultInitValue]
        /\ portDomain = [ self \in ProcSet |-> defaultInitValue]
        /\ sourcePort = [ self \in ProcSet |-> defaultInitValue]
        /\ destPort = [ self \in ProcSet |-> defaultInitValue]
        /\ new_sport = [ self \in ProcSet |-> defaultInitValue]
        /\ good = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure EventSequenceVuln *)
        /\ depth_E = [ self \in ProcSet |-> defaultInitValue]
        /\ i_E = [ self \in ProcSet |-> defaultInitValue]
        /\ j_ = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_E = [ self \in ProcSet |-> defaultInitValue]
        /\ host_E = [ self \in ProcSet |-> defaultInitValue]
        /\ indecies_ = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure EventSequence *)
        /\ depth = [ self \in ProcSet |-> defaultInitValue]
        /\ i_Ev = [ self \in ProcSet |-> defaultInitValue]
        /\ j = [ self \in ProcSet |-> defaultInitValue]
        /\ ip_Ev = [ self \in ProcSet |-> defaultInitValue]
        /\ host_Ev = [ self \in ProcSet |-> defaultInitValue]
        /\ indecies = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure CheckModel *)
        /\ i_C = [ self \in ProcSet |-> defaultInitValue]
        (* Procedure CheckModelVuln *)
        /\ i = [ self \in ProcSet |-> defaultInitValue]
        (* Process Foo *)
        /\ aa = defaultInitValue
        /\ stack = [self \in ProcSet |-> << >>]
        /\ pc = [self \in ProcSet |-> "foo1"]

connectVEvtSeqV(self) == /\ pc[self] = "connectVEvtSeqV"
                         /\ /\ depth_E' = [depth_E EXCEPT ![self] = depth_[self]]
                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequenceVuln",
                                                                     pc        |->  "connectVStart",
                                                                     i_E       |->  i_E[self],
                                                                     j_        |->  j_[self],
                                                                     ip_E      |->  ip_E[self],
                                                                     host_E    |->  host_E[self],
                                                                     indecies_ |->  indecies_[self],
                                                                     depth_E   |->  depth_E[self] ] >>
                                                                 \o stack[self]]
                         /\ i_E' = [i_E EXCEPT ![self] = defaultInitValue]
                         /\ j_' = [j_ EXCEPT ![self] = defaultInitValue]
                         /\ ip_E' = [ip_E EXCEPT ![self] = defaultInitValue]
                         /\ host_E' = [host_E EXCEPT ![self] = defaultInitValue]
                         /\ indecies_' = [indecies_ EXCEPT ![self] = defaultInitValue]
                         /\ pc' = [pc EXCEPT ![self] = "evtSeqVStart"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                         Connections, SendQueue, RcvQueue, MAX, 
                                         Marker1, Marker2, CmdConnect, 
                                         CmdDisconnect, PortSpaceFull, depth_, 
                                         host_, hidx_, host_idx_, pidx_, 
                                         port_idx_, depth_D, ip_, host_D, 
                                         connDomain_, cidx_, conn_, host_Co, 
                                         ip_C, hidx_C, host_idx_C, pidx_C, 
                                         port_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, pkt_Pri, conn_Pr, 
                                         hostMarker_Pri, daddr_P, hostidx_P, 
                                         hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth, i_Ev, j, 
                                         ip_Ev, host_Ev, indecies, i_C, i, aa >>

connectVStart(self) == /\ pc[self] = "connectVStart"
                       /\ IF Len(FreeHosts) > 0
                             THEN /\ PrintT(<<"ConnectVuln:", FreeHosts, FreeHosts>>)
                                  /\ host_idx_' = [host_idx_ EXCEPT ![self] = DOMAIN FreeHosts]
                                  /\ hidx_' = [hidx_ EXCEPT ![self] = CHOOSE h \in host_idx_'[self] : TRUE]
                                  /\ host_' = [host_ EXCEPT ![self] = FreeHosts[hidx_'[self]]]
                                  /\ FreeHosts' = SelectSeq(FreeHosts, LAMBDA a: a /= host_'[self])
                                  /\ UsedHosts' = Append(UsedHosts, host_'[self])
                                  /\ ip_idx' = [ip_idx EXCEPT ![self] = DOMAIN FreeIPs]
                                  /\ ipidx' = [ipidx EXCEPT ![self] = CHOOSE ipp \in ip_idx'[self] : TRUE]
                                  /\ ip' = [ip EXCEPT ![self] = FreeIPs[ipidx'[self]]]
                                  /\ FreeIPs' = SelectSeq(FreeIPs, LAMBDA d: d /= ip'[self])
                                  /\ UsedIPs' = Append(UsedIPs, ip'[self])
                                  /\ Connections' = Append(Connections, <<ip'[self], host_'[self]>>)
                             ELSE /\ TRUE
                                  /\ UNCHANGED << FreeHosts, UsedHosts, 
                                                  FreeIPs, UsedIPs, 
                                                  Connections, host_, hidx_, 
                                                  host_idx_, ip, ip_idx, ipidx >>
                       /\ pc' = [pc EXCEPT ![self] = "connectVRet"]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, SendQueue, RcvQueue, 
                                       MAX, Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, stack, 
                                       depth_, pidx_, port_idx_, depth_D, ip_, 
                                       host_D, connDomain_, cidx_, conn_, 
                                       host_Co, ip_C, hidx_C, host_idx_C, 
                                       pidx_C, port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_Pub, 
                                       host_Pub, depth_Pri, pkt, conn_Priv, 
                                       hostMarker, daddr, hostidx, hidx, 
                                       otherEntry, i_Pri, indicies, portDomain, 
                                       sourcePort, destPort, new_sport, good, 
                                       depth_E, i_E, j_, ip_E, host_E, 
                                       indecies_, depth, i_Ev, j, ip_Ev, 
                                       host_Ev, indecies, i_C, i, aa >>

connectVRet(self) == /\ pc[self] = "connectVRet"
                     /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                     /\ host_' = [host_ EXCEPT ![self] = Head(stack[self]).host_]
                     /\ hidx_' = [hidx_ EXCEPT ![self] = Head(stack[self]).hidx_]
                     /\ host_idx_' = [host_idx_ EXCEPT ![self] = Head(stack[self]).host_idx_]
                     /\ pidx_' = [pidx_ EXCEPT ![self] = Head(stack[self]).pidx_]
                     /\ port_idx_' = [port_idx_ EXCEPT ![self] = Head(stack[self]).port_idx_]
                     /\ depth_' = [depth_ EXCEPT ![self] = Head(stack[self]).depth_]
                     /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                     /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                     Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, 
                                     Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, 
                                     H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                     PortMap2, TableFull, EvictionReroute, 
                                     PortScanInv, MaxTableSize, hosts, 
                                     FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                     ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                     Connections, SendQueue, RcvQueue, MAX, 
                                     Marker1, Marker2, CmdConnect, 
                                     CmdDisconnect, PortSpaceFull, depth_D, 
                                     ip_, host_D, connDomain_, cidx_, conn_, 
                                     host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                     port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                     cidx_D, conn_D, host, ip, connDomain_Di, 
                                     cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                     entry_, conn_P, hostMarker_, ip_idx_, 
                                     ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                     entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                     ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                     dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                     daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                     indicies_, portDomain_, sourcePort_, 
                                     destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                     conn_Pr, hostMarker_Pri, daddr_P, 
                                     hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                     indicies_P, portDomain_P, sourcePort_P, 
                                     destPort_P, new_sport_P, pkt_Priv, 
                                     conn_Pri, hostMarker_Priv, daddr_Pr, 
                                     hostidx_Pr, hidx_Pri, otherEntry_Pr, i_Pr, 
                                     indicies_Pr, portDomain_Pr, sourcePort_Pr, 
                                     destPort_Pr, new_sport_Pr, depth_C, 
                                     host_C, hidx_Co, host_idx, pidx, port_idx, 
                                     depth_Di, ip_D, host_Di, connDomain, cidx, 
                                     conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                     conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                     ip_Pub, host_Pub, depth_Pri, pkt, 
                                     conn_Priv, hostMarker, daddr, hostidx, 
                                     hidx, otherEntry, i_Pri, indicies, 
                                     portDomain, sourcePort, destPort, 
                                     new_sport, good, depth_E, i_E, j_, ip_E, 
                                     host_E, indecies_, depth, i_Ev, j, ip_Ev, 
                                     host_Ev, indecies, i_C, i, aa >>

ConnectVuln(self) == connectVEvtSeqV(self) \/ connectVStart(self)
                        \/ connectVRet(self)

disconnectVEvtSV(self) == /\ pc[self] = "disconnectVEvtSV"
                          /\ /\ depth_E' = [depth_E EXCEPT ![self] = depth_D[self]]
                             /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequenceVuln",
                                                                      pc        |->  "disconnectVStart",
                                                                      i_E       |->  i_E[self],
                                                                      j_        |->  j_[self],
                                                                      ip_E      |->  ip_E[self],
                                                                      host_E    |->  host_E[self],
                                                                      indecies_ |->  indecies_[self],
                                                                      depth_E   |->  depth_E[self] ] >>
                                                                  \o stack[self]]
                          /\ i_E' = [i_E EXCEPT ![self] = defaultInitValue]
                          /\ j_' = [j_ EXCEPT ![self] = defaultInitValue]
                          /\ ip_E' = [ip_E EXCEPT ![self] = defaultInitValue]
                          /\ host_E' = [host_E EXCEPT ![self] = defaultInitValue]
                          /\ indecies_' = [indecies_ EXCEPT ![self] = defaultInitValue]
                          /\ pc' = [pc EXCEPT ![self] = "evtSeqVStart"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          FreeHosts, UsedHosts, Ports, 
                                          ExtraPorts, ExtraExtraPorts, T, 
                                          FreeIPs, UsedIPs, Connections, 
                                          SendQueue, RcvQueue, MAX, Marker1, 
                                          Marker2, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, depth_, host_, hidx_, 
                                          host_idx_, pidx_, port_idx_, depth_D, 
                                          ip_, host_D, connDomain_, cidx_, 
                                          conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, conn_Pub, hostMarker_Pu, 
                                          ip_idx, ipidx, ip_Pub, host_Pub, 
                                          depth_Pri, pkt, conn_Priv, 
                                          hostMarker, daddr, hostidx, hidx, 
                                          otherEntry, i_Pri, indicies, 
                                          portDomain, sourcePort, destPort, 
                                          new_sport, good, depth, i_Ev, j, 
                                          ip_Ev, host_Ev, indecies, i_C, i, aa >>

disconnectVStart(self) == /\ pc[self] = "disconnectVStart"
                          /\ IF Len(Connections) > 0
                                THEN /\ connDomain_' = [connDomain_ EXCEPT ![self] = DOMAIN Connections]
                                     /\ cidx_' = [cidx_ EXCEPT ![self] = CHOOSE c \in connDomain_'[self] : TRUE]
                                     /\ conn_' = [conn_ EXCEPT ![self] = Connections[cidx_'[self]]]
                                     /\ ip_' = [ip_ EXCEPT ![self] = conn_'[self][1]]
                                     /\ host_D' = [host_D EXCEPT ![self] = conn_'[self][2]]
                                     /\ PrintT(<< "Disconnect- Before:", host_D'[self], ip_'[self], Connections>>)
                                     /\ Connections' = SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip_'[self])
                                     /\ UsedIPs' = SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip_'[self])
                                     /\ FreeIPs' = Append(FreeIPs, ip_'[self])
                                     /\ FreeHosts' = Append(FreeHosts, host_D'[self])
                                     /\ UsedHosts' = SelectSeq(UsedHosts, LAMBDA m: m /= host_D'[self])
                                     /\ PrintT(<< "Disconnect- After: ", host_D'[self], ip_'[self], Connections'>>)
                                ELSE /\ TRUE
                                     /\ UNCHANGED << FreeHosts, UsedHosts, 
                                                     FreeIPs, UsedIPs, 
                                                     Connections, ip_, host_D, 
                                                     connDomain_, cidx_, conn_ >>
                          /\ pc' = [pc EXCEPT ![self] = "disconnectRet_"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          Ports, ExtraPorts, ExtraExtraPorts, 
                                          T, SendQueue, RcvQueue, MAX, Marker1, 
                                          Marker2, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, stack, depth_, host_, 
                                          hidx_, host_idx_, pidx_, port_idx_, 
                                          depth_D, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, conn_Pub, hostMarker_Pu, 
                                          ip_idx, ipidx, ip_Pub, host_Pub, 
                                          depth_Pri, pkt, conn_Priv, 
                                          hostMarker, daddr, hostidx, hidx, 
                                          otherEntry, i_Pri, indicies, 
                                          portDomain, sourcePort, destPort, 
                                          new_sport, good, depth_E, i_E, j_, 
                                          ip_E, host_E, indecies_, depth, i_Ev, 
                                          j, ip_Ev, host_Ev, indecies, i_C, i, 
                                          aa >>

disconnectRet_(self) == /\ pc[self] = "disconnectRet_"
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ ip_' = [ip_ EXCEPT ![self] = Head(stack[self]).ip_]
                        /\ host_D' = [host_D EXCEPT ![self] = Head(stack[self]).host_D]
                        /\ connDomain_' = [connDomain_ EXCEPT ![self] = Head(stack[self]).connDomain_]
                        /\ cidx_' = [cidx_ EXCEPT ![self] = Head(stack[self]).cidx_]
                        /\ conn_' = [conn_ EXCEPT ![self] = Head(stack[self]).conn_]
                        /\ depth_D' = [depth_D EXCEPT ![self] = Head(stack[self]).depth_D]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, SendQueue, RcvQueue, MAX, 
                                        Marker1, Marker2, CmdConnect, 
                                        CmdDisconnect, PortSpaceFull, depth_, 
                                        host_, hidx_, host_idx_, pidx_, 
                                        port_idx_, host_Co, ip_C, hidx_C, 
                                        host_idx_C, pidx_C, port_idx_C, 
                                        host_Dis, ip_Di, connDomain_D, cidx_D, 
                                        conn_D, host, ip, connDomain_Di, 
                                        cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                        entry_, conn_P, hostMarker_, ip_idx_, 
                                        ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                        entry_P, conn_Pu, hostMarker_P, 
                                        ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                        conn, sport, dstAddr, dport, pkt_Pr, 
                                        hostMarker_Pr, daddr_, hostidx_, 
                                        hidx_P, otherEntry_, i_, indicies_, 
                                        portDomain_, sourcePort_, destPort_, 
                                        new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth_E, 
                                        i_E, j_, ip_E, host_E, indecies_, 
                                        depth, i_Ev, j, ip_Ev, host_Ev, 
                                        indecies, i_C, i, aa >>

DisconnectVuln(self) == disconnectVEvtSV(self) \/ disconnectVStart(self)
                           \/ disconnectRet_(self)

connectManStart(self) == /\ pc[self] = "connectManStart"
                         /\ IF Len(FreeHosts) > 0
                               THEN /\ PrintT(<< "ConnectMan - BEFORE ", FreeHosts, FreeIPs, Connections>>)
                                    /\ FreeIPs' = SelectSeq(FreeIPs, LAMBDA e: ~(e=ip_C[self]))
                                    /\ UsedIPs' = Append(UsedIPs, ip_C[self])
                                    /\ FreeHosts' = SelectSeq(FreeHosts, LAMBDA a: a /= host_Co[self])
                                    /\ UsedHosts' = Append(UsedHosts, host_Co[self])
                                    /\ Connections' = Append(Connections,  <<ip_C[self], host_Co[self]>>)
                                    /\ PrintT(<< "ConnectMan - AFTER ", FreeHosts', FreeIPs', Connections'>>)
                                    /\ port_idx_C' = [port_idx_C EXCEPT ![self] = DOMAIN Ports]
                                    /\ pidx_C' = [pidx_C EXCEPT ![self] = CHOOSE p \in port_idx_C'[self] : TRUE]
                               ELSE /\ TRUE
                                    /\ UNCHANGED << FreeHosts, UsedHosts, 
                                                    FreeIPs, UsedIPs, 
                                                    Connections, pidx_C, 
                                                    port_idx_C >>
                         /\ pc' = [pc EXCEPT ![self] = "connectManRet"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, Ports, 
                                         ExtraPorts, ExtraExtraPorts, T, 
                                         SendQueue, RcvQueue, MAX, Marker1, 
                                         Marker2, CmdConnect, CmdDisconnect, 
                                         PortSpaceFull, stack, depth_, host_, 
                                         hidx_, host_idx_, pidx_, port_idx_, 
                                         depth_D, ip_, host_D, connDomain_, 
                                         cidx_, conn_, host_Co, ip_C, hidx_C, 
                                         host_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, pkt_Pri, conn_Pr, 
                                         hostMarker_Pri, daddr_P, hostidx_P, 
                                         hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth_E, i_E, j_, 
                                         ip_E, host_E, indecies_, depth, i_Ev, 
                                         j, ip_Ev, host_Ev, indecies, i_C, i, 
                                         aa >>

connectManRet(self) == /\ pc[self] = "connectManRet"
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ hidx_C' = [hidx_C EXCEPT ![self] = Head(stack[self]).hidx_C]
                       /\ host_idx_C' = [host_idx_C EXCEPT ![self] = Head(stack[self]).host_idx_C]
                       /\ pidx_C' = [pidx_C EXCEPT ![self] = Head(stack[self]).pidx_C]
                       /\ port_idx_C' = [port_idx_C EXCEPT ![self] = Head(stack[self]).port_idx_C]
                       /\ host_Co' = [host_Co EXCEPT ![self] = Head(stack[self]).host_Co]
                       /\ ip_C' = [ip_C EXCEPT ![self] = Head(stack[self]).ip_C]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, depth_, 
                                       host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Dis, 
                                       ip_Di, connDomain_D, cidx_D, conn_D, 
                                       host, ip, connDomain_Di, cidx_Di, 
                                       conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                       conn_P, hostMarker_, ip_idx_, ipidx_, 
                                       ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                       conn_Pu, hostMarker_P, ip_idx_P, 
                                       ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                       dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                       daddr_, hostidx_, hidx_P, otherEntry_, 
                                       i_, indicies_, portDomain_, sourcePort_, 
                                       destPort_, new_sport_, depth_Pr, 
                                       pkt_Pri, conn_Pr, hostMarker_Pri, 
                                       daddr_P, hostidx_P, hidx_Pr, 
                                       otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i_C, i, aa >>

ConnectMan(self) == connectManStart(self) \/ connectManRet(self)

disconnectManStart(self) == /\ pc[self] = "disconnectManStart"
                            /\ IF Len(Connections) > 0
                                  THEN /\ PrintT(<< "DisconnectMan - Before:", host_Dis[self], ip_Di[self], Connections>>)
                                       /\ Connections' = SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip_Di[self])
                                       /\ UsedIPs' = SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip_Di[self])
                                       /\ FreeIPs' = Append(FreeIPs, ip_Di[self])
                                       /\ FreeHosts' = Append(FreeHosts, host_Dis[self])
                                       /\ UsedHosts' = SelectSeq(UsedHosts, LAMBDA m: m /= host_Dis[self])
                                       /\ PrintT(<< "DisconnectMan - After: ", host_Dis[self], ip_Di[self], Connections'>>)
                                       /\ pc' = [pc EXCEPT ![self] = "disconnectVulnPurgeOrphans1"]
                                  ELSE /\ pc' = [pc EXCEPT ![self] = "disconnectManRet"]
                                       /\ UNCHANGED << FreeHosts, UsedHosts, 
                                                       FreeIPs, UsedIPs, 
                                                       Connections >>
                            /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                            Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                            Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                            Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                            EP1, PortMap1, EP2, PortMap2, 
                                            TableFull, EvictionReroute, 
                                            PortScanInv, MaxTableSize, hosts, 
                                            Ports, ExtraPorts, ExtraExtraPorts, 
                                            T, SendQueue, RcvQueue, MAX, 
                                            Marker1, Marker2, CmdConnect, 
                                            CmdDisconnect, PortSpaceFull, 
                                            stack, depth_, host_, hidx_, 
                                            host_idx_, pidx_, port_idx_, 
                                            depth_D, ip_, host_D, connDomain_, 
                                            cidx_, conn_, host_Co, ip_C, 
                                            hidx_C, host_idx_C, pidx_C, 
                                            port_idx_C, host_Dis, ip_Di, 
                                            connDomain_D, cidx_D, conn_D, host, 
                                            ip, connDomain_Di, cidx_Di, 
                                            conn_Di, depth_P, pkt_, ipkt_, 
                                            entry_, conn_P, hostMarker_, 
                                            ip_idx_, ipidx_, ip_P, host_P, 
                                            pkt_P, ipkt_P, entry_P, conn_Pu, 
                                            hostMarker_P, ip_idx_P, ipidx_P, 
                                            ip_Pu, host_Pu, conn, sport, 
                                            dstAddr, dport, pkt_Pr, 
                                            hostMarker_Pr, daddr_, hostidx_, 
                                            hidx_P, otherEntry_, i_, indicies_, 
                                            portDomain_, sourcePort_, 
                                            destPort_, new_sport_, depth_Pr, 
                                            pkt_Pri, conn_Pr, hostMarker_Pri, 
                                            daddr_P, hostidx_P, hidx_Pr, 
                                            otherEntry_P, i_P, indicies_P, 
                                            portDomain_P, sourcePort_P, 
                                            destPort_P, new_sport_P, pkt_Priv, 
                                            conn_Pri, hostMarker_Priv, 
                                            daddr_Pr, hostidx_Pr, hidx_Pri, 
                                            otherEntry_Pr, i_Pr, indicies_Pr, 
                                            portDomain_Pr, sourcePort_Pr, 
                                            destPort_Pr, new_sport_Pr, depth_C, 
                                            host_C, hidx_Co, host_idx, pidx, 
                                            port_idx, depth_Di, ip_D, host_Di, 
                                            connDomain, cidx, conn_Dis, 
                                            depth_Pu, pkt_Pu, ipkt, entry, 
                                            conn_Pub, hostMarker_Pu, ip_idx, 
                                            ipidx, ip_Pub, host_Pub, depth_Pri, 
                                            pkt, conn_Priv, hostMarker, daddr, 
                                            hostidx, hidx, otherEntry, i_Pri, 
                                            indicies, portDomain, sourcePort, 
                                            destPort, new_sport, good, depth_E, 
                                            i_E, j_, ip_E, host_E, indecies_, 
                                            depth, i_Ev, j, ip_Ev, host_Ev, 
                                            indecies, i_C, i, aa >>

disconnectVulnPurgeOrphans1(self) == /\ pc[self] = "disconnectVulnPurgeOrphans1"
                                     /\ T' = SelectSeq(T, LAMBDA e: e.orig.saddr /= ip_Di[self])
                                     /\ pc' = [pc EXCEPT ![self] = "disconnectVulnPurgeOrphans2"]
                                     /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, 
                                                     Cc, Dd, Ee, Ff, Gg, Hh, 
                                                     Ii, Jj, Kk, Ll, Mm, Nn, 
                                                     Oo, Pp, Qq, Rr, Ss, Tt, 
                                                     Uu, Vv, Ww, Xx, Yy, Zz, 
                                                     H1, H2, MaxPorts, EP1, 
                                                     PortMap1, EP2, PortMap2, 
                                                     TableFull, 
                                                     EvictionReroute, 
                                                     PortScanInv, MaxTableSize, 
                                                     hosts, FreeHosts, 
                                                     UsedHosts, Ports, 
                                                     ExtraPorts, 
                                                     ExtraExtraPorts, FreeIPs, 
                                                     UsedIPs, Connections, 
                                                     SendQueue, RcvQueue, MAX, 
                                                     Marker1, Marker2, 
                                                     CmdConnect, CmdDisconnect, 
                                                     PortSpaceFull, stack, 
                                                     depth_, host_, hidx_, 
                                                     host_idx_, pidx_, 
                                                     port_idx_, depth_D, ip_, 
                                                     host_D, connDomain_, 
                                                     cidx_, conn_, host_Co, 
                                                     ip_C, hidx_C, host_idx_C, 
                                                     pidx_C, port_idx_C, 
                                                     host_Dis, ip_Di, 
                                                     connDomain_D, cidx_D, 
                                                     conn_D, host, ip, 
                                                     connDomain_Di, cidx_Di, 
                                                     conn_Di, depth_P, pkt_, 
                                                     ipkt_, entry_, conn_P, 
                                                     hostMarker_, ip_idx_, 
                                                     ipidx_, ip_P, host_P, 
                                                     pkt_P, ipkt_P, entry_P, 
                                                     conn_Pu, hostMarker_P, 
                                                     ip_idx_P, ipidx_P, ip_Pu, 
                                                     host_Pu, conn, sport, 
                                                     dstAddr, dport, pkt_Pr, 
                                                     hostMarker_Pr, daddr_, 
                                                     hostidx_, hidx_P, 
                                                     otherEntry_, i_, 
                                                     indicies_, portDomain_, 
                                                     sourcePort_, destPort_, 
                                                     new_sport_, depth_Pr, 
                                                     pkt_Pri, conn_Pr, 
                                                     hostMarker_Pri, daddr_P, 
                                                     hostidx_P, hidx_Pr, 
                                                     otherEntry_P, i_P, 
                                                     indicies_P, portDomain_P, 
                                                     sourcePort_P, destPort_P, 
                                                     new_sport_P, pkt_Priv, 
                                                     conn_Pri, hostMarker_Priv, 
                                                     daddr_Pr, hostidx_Pr, 
                                                     hidx_Pri, otherEntry_Pr, 
                                                     i_Pr, indicies_Pr, 
                                                     portDomain_Pr, 
                                                     sourcePort_Pr, 
                                                     destPort_Pr, new_sport_Pr, 
                                                     depth_C, host_C, hidx_Co, 
                                                     host_idx, pidx, port_idx, 
                                                     depth_Di, ip_D, host_Di, 
                                                     connDomain, cidx, 
                                                     conn_Dis, depth_Pu, 
                                                     pkt_Pu, ipkt, entry, 
                                                     conn_Pub, hostMarker_Pu, 
                                                     ip_idx, ipidx, ip_Pub, 
                                                     host_Pub, depth_Pri, pkt, 
                                                     conn_Priv, hostMarker, 
                                                     daddr, hostidx, hidx, 
                                                     otherEntry, i_Pri, 
                                                     indicies, portDomain, 
                                                     sourcePort, destPort, 
                                                     new_sport, good, depth_E, 
                                                     i_E, j_, ip_E, host_E, 
                                                     indecies_, depth, i_Ev, j, 
                                                     ip_Ev, host_Ev, indecies, 
                                                     i_C, i, aa >>

disconnectVulnPurgeOrphans2(self) == /\ pc[self] = "disconnectVulnPurgeOrphans2"
                                     /\ T' = SelectSeq(T, LAMBDA e: e.orig.saddr /= host_Dis[self])
                                     /\ IF host_Dis[self]=H1
                                           THEN /\ PortMap1' = <<>>
                                                /\ UNCHANGED PortMap2
                                           ELSE /\ PortMap2' = <<>>
                                                /\ UNCHANGED PortMap1
                                     /\ pc' = [pc EXCEPT ![self] = "disconnectManRet"]
                                     /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, 
                                                     Cc, Dd, Ee, Ff, Gg, Hh, 
                                                     Ii, Jj, Kk, Ll, Mm, Nn, 
                                                     Oo, Pp, Qq, Rr, Ss, Tt, 
                                                     Uu, Vv, Ww, Xx, Yy, Zz, 
                                                     H1, H2, MaxPorts, EP1, 
                                                     EP2, TableFull, 
                                                     EvictionReroute, 
                                                     PortScanInv, MaxTableSize, 
                                                     hosts, FreeHosts, 
                                                     UsedHosts, Ports, 
                                                     ExtraPorts, 
                                                     ExtraExtraPorts, FreeIPs, 
                                                     UsedIPs, Connections, 
                                                     SendQueue, RcvQueue, MAX, 
                                                     Marker1, Marker2, 
                                                     CmdConnect, CmdDisconnect, 
                                                     PortSpaceFull, stack, 
                                                     depth_, host_, hidx_, 
                                                     host_idx_, pidx_, 
                                                     port_idx_, depth_D, ip_, 
                                                     host_D, connDomain_, 
                                                     cidx_, conn_, host_Co, 
                                                     ip_C, hidx_C, host_idx_C, 
                                                     pidx_C, port_idx_C, 
                                                     host_Dis, ip_Di, 
                                                     connDomain_D, cidx_D, 
                                                     conn_D, host, ip, 
                                                     connDomain_Di, cidx_Di, 
                                                     conn_Di, depth_P, pkt_, 
                                                     ipkt_, entry_, conn_P, 
                                                     hostMarker_, ip_idx_, 
                                                     ipidx_, ip_P, host_P, 
                                                     pkt_P, ipkt_P, entry_P, 
                                                     conn_Pu, hostMarker_P, 
                                                     ip_idx_P, ipidx_P, ip_Pu, 
                                                     host_Pu, conn, sport, 
                                                     dstAddr, dport, pkt_Pr, 
                                                     hostMarker_Pr, daddr_, 
                                                     hostidx_, hidx_P, 
                                                     otherEntry_, i_, 
                                                     indicies_, portDomain_, 
                                                     sourcePort_, destPort_, 
                                                     new_sport_, depth_Pr, 
                                                     pkt_Pri, conn_Pr, 
                                                     hostMarker_Pri, daddr_P, 
                                                     hostidx_P, hidx_Pr, 
                                                     otherEntry_P, i_P, 
                                                     indicies_P, portDomain_P, 
                                                     sourcePort_P, destPort_P, 
                                                     new_sport_P, pkt_Priv, 
                                                     conn_Pri, hostMarker_Priv, 
                                                     daddr_Pr, hostidx_Pr, 
                                                     hidx_Pri, otherEntry_Pr, 
                                                     i_Pr, indicies_Pr, 
                                                     portDomain_Pr, 
                                                     sourcePort_Pr, 
                                                     destPort_Pr, new_sport_Pr, 
                                                     depth_C, host_C, hidx_Co, 
                                                     host_idx, pidx, port_idx, 
                                                     depth_Di, ip_D, host_Di, 
                                                     connDomain, cidx, 
                                                     conn_Dis, depth_Pu, 
                                                     pkt_Pu, ipkt, entry, 
                                                     conn_Pub, hostMarker_Pu, 
                                                     ip_idx, ipidx, ip_Pub, 
                                                     host_Pub, depth_Pri, pkt, 
                                                     conn_Priv, hostMarker, 
                                                     daddr, hostidx, hidx, 
                                                     otherEntry, i_Pri, 
                                                     indicies, portDomain, 
                                                     sourcePort, destPort, 
                                                     new_sport, good, depth_E, 
                                                     i_E, j_, ip_E, host_E, 
                                                     indecies_, depth, i_Ev, j, 
                                                     ip_Ev, host_Ev, indecies, 
                                                     i_C, i, aa >>

disconnectManRet(self) == /\ pc[self] = "disconnectManRet"
                          /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                          /\ connDomain_D' = [connDomain_D EXCEPT ![self] = Head(stack[self]).connDomain_D]
                          /\ cidx_D' = [cidx_D EXCEPT ![self] = Head(stack[self]).cidx_D]
                          /\ conn_D' = [conn_D EXCEPT ![self] = Head(stack[self]).conn_D]
                          /\ host_Dis' = [host_Dis EXCEPT ![self] = Head(stack[self]).host_Dis]
                          /\ ip_Di' = [ip_Di EXCEPT ![self] = Head(stack[self]).ip_Di]
                          /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          FreeHosts, UsedHosts, Ports, 
                                          ExtraPorts, ExtraExtraPorts, T, 
                                          FreeIPs, UsedIPs, Connections, 
                                          SendQueue, RcvQueue, MAX, Marker1, 
                                          Marker2, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, depth_, host_, hidx_, 
                                          host_idx_, pidx_, port_idx_, depth_D, 
                                          ip_, host_D, connDomain_, cidx_, 
                                          conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, host, 
                                          ip, connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, conn_Pub, hostMarker_Pu, 
                                          ip_idx, ipidx, ip_Pub, host_Pub, 
                                          depth_Pri, pkt, conn_Priv, 
                                          hostMarker, daddr, hostidx, hidx, 
                                          otherEntry, i_Pri, indicies, 
                                          portDomain, sourcePort, destPort, 
                                          new_sport, good, depth_E, i_E, j_, 
                                          ip_E, host_E, indecies_, depth, i_Ev, 
                                          j, ip_Ev, host_Ev, indecies, i_C, i, 
                                          aa >>

DisconnectMan(self) == disconnectManStart(self)
                          \/ disconnectVulnPurgeOrphans1(self)
                          \/ disconnectVulnPurgeOrphans2(self)
                          \/ disconnectManRet(self)

disconnectVulnManStart(self) == /\ pc[self] = "disconnectVulnManStart"
                                /\ IF Len(Connections) > 0
                                      THEN /\ PrintT(<< "DisconnectVulnMan- Before:", host[self], ip[self], Connections>>)
                                           /\ Connections' = SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip[self])
                                           /\ UsedIPs' = SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip[self])
                                           /\ FreeIPs' = Append(FreeIPs, ip[self])
                                           /\ FreeHosts' = Append(FreeHosts, host[self])
                                           /\ UsedHosts' = SelectSeq(UsedHosts, LAMBDA m: m /= host[self])
                                           /\ PrintT(<< "DisconnectVulnMan - After: ", host[self], ip[self], Connections'>>)
                                      ELSE /\ TRUE
                                           /\ UNCHANGED << FreeHosts, 
                                                           UsedHosts, FreeIPs, 
                                                           UsedIPs, 
                                                           Connections >>
                                /\ pc' = [pc EXCEPT ![self] = "disconnectVulnManRet"]
                                /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, 
                                                Dd, Ee, Ff, Gg, Hh, Ii, Jj, Kk, 
                                                Ll, Mm, Nn, Oo, Pp, Qq, Rr, Ss, 
                                                Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, 
                                                H2, MaxPorts, EP1, PortMap1, 
                                                EP2, PortMap2, TableFull, 
                                                EvictionReroute, PortScanInv, 
                                                MaxTableSize, hosts, Ports, 
                                                ExtraPorts, ExtraExtraPorts, T, 
                                                SendQueue, RcvQueue, MAX, 
                                                Marker1, Marker2, CmdConnect, 
                                                CmdDisconnect, PortSpaceFull, 
                                                stack, depth_, host_, hidx_, 
                                                host_idx_, pidx_, port_idx_, 
                                                depth_D, ip_, host_D, 
                                                connDomain_, cidx_, conn_, 
                                                host_Co, ip_C, hidx_C, 
                                                host_idx_C, pidx_C, port_idx_C, 
                                                host_Dis, ip_Di, connDomain_D, 
                                                cidx_D, conn_D, host, ip, 
                                                connDomain_Di, cidx_Di, 
                                                conn_Di, depth_P, pkt_, ipkt_, 
                                                entry_, conn_P, hostMarker_, 
                                                ip_idx_, ipidx_, ip_P, host_P, 
                                                pkt_P, ipkt_P, entry_P, 
                                                conn_Pu, hostMarker_P, 
                                                ip_idx_P, ipidx_P, ip_Pu, 
                                                host_Pu, conn, sport, dstAddr, 
                                                dport, pkt_Pr, hostMarker_Pr, 
                                                daddr_, hostidx_, hidx_P, 
                                                otherEntry_, i_, indicies_, 
                                                portDomain_, sourcePort_, 
                                                destPort_, new_sport_, 
                                                depth_Pr, pkt_Pri, conn_Pr, 
                                                hostMarker_Pri, daddr_P, 
                                                hostidx_P, hidx_Pr, 
                                                otherEntry_P, i_P, indicies_P, 
                                                portDomain_P, sourcePort_P, 
                                                destPort_P, new_sport_P, 
                                                pkt_Priv, conn_Pri, 
                                                hostMarker_Priv, daddr_Pr, 
                                                hostidx_Pr, hidx_Pri, 
                                                otherEntry_Pr, i_Pr, 
                                                indicies_Pr, portDomain_Pr, 
                                                sourcePort_Pr, destPort_Pr, 
                                                new_sport_Pr, depth_C, host_C, 
                                                hidx_Co, host_idx, pidx, 
                                                port_idx, depth_Di, ip_D, 
                                                host_Di, connDomain, cidx, 
                                                conn_Dis, depth_Pu, pkt_Pu, 
                                                ipkt, entry, conn_Pub, 
                                                hostMarker_Pu, ip_idx, ipidx, 
                                                ip_Pub, host_Pub, depth_Pri, 
                                                pkt, conn_Priv, hostMarker, 
                                                daddr, hostidx, hidx, 
                                                otherEntry, i_Pri, indicies, 
                                                portDomain, sourcePort, 
                                                destPort, new_sport, good, 
                                                depth_E, i_E, j_, ip_E, host_E, 
                                                indecies_, depth, i_Ev, j, 
                                                ip_Ev, host_Ev, indecies, i_C, 
                                                i, aa >>

disconnectVulnManRet(self) == /\ pc[self] = "disconnectVulnManRet"
                              /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                              /\ connDomain_Di' = [connDomain_Di EXCEPT ![self] = Head(stack[self]).connDomain_Di]
                              /\ cidx_Di' = [cidx_Di EXCEPT ![self] = Head(stack[self]).cidx_Di]
                              /\ conn_Di' = [conn_Di EXCEPT ![self] = Head(stack[self]).conn_Di]
                              /\ host' = [host EXCEPT ![self] = Head(stack[self]).host]
                              /\ ip' = [ip EXCEPT ![self] = Head(stack[self]).ip]
                              /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                              /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, 
                                              Dd, Ee, Ff, Gg, Hh, Ii, Jj, Kk, 
                                              Ll, Mm, Nn, Oo, Pp, Qq, Rr, Ss, 
                                              Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, 
                                              H2, MaxPorts, EP1, PortMap1, EP2, 
                                              PortMap2, TableFull, 
                                              EvictionReroute, PortScanInv, 
                                              MaxTableSize, hosts, FreeHosts, 
                                              UsedHosts, Ports, ExtraPorts, 
                                              ExtraExtraPorts, T, FreeIPs, 
                                              UsedIPs, Connections, SendQueue, 
                                              RcvQueue, MAX, Marker1, Marker2, 
                                              CmdConnect, CmdDisconnect, 
                                              PortSpaceFull, depth_, host_, 
                                              hidx_, host_idx_, pidx_, 
                                              port_idx_, depth_D, ip_, host_D, 
                                              connDomain_, cidx_, conn_, 
                                              host_Co, ip_C, hidx_C, 
                                              host_idx_C, pidx_C, port_idx_C, 
                                              host_Dis, ip_Di, connDomain_D, 
                                              cidx_D, conn_D, depth_P, pkt_, 
                                              ipkt_, entry_, conn_P, 
                                              hostMarker_, ip_idx_, ipidx_, 
                                              ip_P, host_P, pkt_P, ipkt_P, 
                                              entry_P, conn_Pu, hostMarker_P, 
                                              ip_idx_P, ipidx_P, ip_Pu, 
                                              host_Pu, conn, sport, dstAddr, 
                                              dport, pkt_Pr, hostMarker_Pr, 
                                              daddr_, hostidx_, hidx_P, 
                                              otherEntry_, i_, indicies_, 
                                              portDomain_, sourcePort_, 
                                              destPort_, new_sport_, depth_Pr, 
                                              pkt_Pri, conn_Pr, hostMarker_Pri, 
                                              daddr_P, hostidx_P, hidx_Pr, 
                                              otherEntry_P, i_P, indicies_P, 
                                              portDomain_P, sourcePort_P, 
                                              destPort_P, new_sport_P, 
                                              pkt_Priv, conn_Pri, 
                                              hostMarker_Priv, daddr_Pr, 
                                              hostidx_Pr, hidx_Pri, 
                                              otherEntry_Pr, i_Pr, indicies_Pr, 
                                              portDomain_Pr, sourcePort_Pr, 
                                              destPort_Pr, new_sport_Pr, 
                                              depth_C, host_C, hidx_Co, 
                                              host_idx, pidx, port_idx, 
                                              depth_Di, ip_D, host_Di, 
                                              connDomain, cidx, conn_Dis, 
                                              depth_Pu, pkt_Pu, ipkt, entry, 
                                              conn_Pub, hostMarker_Pu, ip_idx, 
                                              ipidx, ip_Pub, host_Pub, 
                                              depth_Pri, pkt, conn_Priv, 
                                              hostMarker, daddr, hostidx, hidx, 
                                              otherEntry, i_Pri, indicies, 
                                              portDomain, sourcePort, destPort, 
                                              new_sport, good, depth_E, i_E, 
                                              j_, ip_E, host_E, indecies_, 
                                              depth, i_Ev, j, ip_Ev, host_Ev, 
                                              indecies, i_C, i, aa >>

DisconnectVulnMan(self) == disconnectVulnManStart(self)
                              \/ disconnectVulnManRet(self)

evictStart(self) == /\ pc[self] = "evictStart"
                    /\ PrintT("Evict")
                    /\ IF Len(T) > 0
                          THEN /\ T' = Tail(T)
                          ELSE /\ TRUE
                               /\ T' = T
                    /\ pc' = [pc EXCEPT ![self] = "evictRet"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    stack, depth_, host_, hidx_, host_idx_, 
                                    pidx_, port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

evictRet(self) == /\ pc[self] = "evictRet"
                  /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                  /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                  Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                  Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                  MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                  TableFull, EvictionReroute, PortScanInv, 
                                  MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                  Ports, ExtraPorts, ExtraExtraPorts, T, 
                                  FreeIPs, UsedIPs, Connections, SendQueue, 
                                  RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                  CmdDisconnect, PortSpaceFull, depth_, host_, 
                                  hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                  ip_, host_D, connDomain_, cidx_, conn_, 
                                  host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                  port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                  cidx_D, conn_D, host, ip, connDomain_Di, 
                                  cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                  entry_, conn_P, hostMarker_, ip_idx_, ipidx_, 
                                  ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                  conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                  ip_Pu, host_Pu, conn, sport, dstAddr, dport, 
                                  pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                  hidx_P, otherEntry_, i_, indicies_, 
                                  portDomain_, sourcePort_, destPort_, 
                                  new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                  hostMarker_Pri, daddr_P, hostidx_P, hidx_Pr, 
                                  otherEntry_P, i_P, indicies_P, portDomain_P, 
                                  sourcePort_P, destPort_P, new_sport_P, 
                                  pkt_Priv, conn_Pri, hostMarker_Priv, 
                                  daddr_Pr, hostidx_Pr, hidx_Pri, 
                                  otherEntry_Pr, i_Pr, indicies_Pr, 
                                  portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                  new_sport_Pr, depth_C, host_C, hidx_Co, 
                                  host_idx, pidx, port_idx, depth_Di, ip_D, 
                                  host_Di, connDomain, cidx, conn_Dis, 
                                  depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                  hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                  host_Pub, depth_Pri, pkt, conn_Priv, 
                                  hostMarker, daddr, hostidx, hidx, otherEntry, 
                                  i_Pri, indicies, portDomain, sourcePort, 
                                  destPort, new_sport, good, depth_E, i_E, j_, 
                                  ip_E, host_E, indecies_, depth, i_Ev, j, 
                                  ip_Ev, host_Ev, indecies, i_C, i, aa >>

Evict(self) == evictStart(self) \/ evictRet(self)

pubtoprivVEvt3(self) == /\ pc[self] = "pubtoprivVEvt3"
                        /\ /\ depth_E' = [depth_E EXCEPT ![self] = depth_P[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequenceVuln",
                                                                    pc        |->  "pubtoprivVStart",
                                                                    i_E       |->  i_E[self],
                                                                    j_        |->  j_[self],
                                                                    ip_E      |->  ip_E[self],
                                                                    host_E    |->  host_E[self],
                                                                    indecies_ |->  indecies_[self],
                                                                    depth_E   |->  depth_E[self] ] >>
                                                                \o stack[self]]
                        /\ i_E' = [i_E EXCEPT ![self] = defaultInitValue]
                        /\ j_' = [j_ EXCEPT ![self] = defaultInitValue]
                        /\ ip_E' = [ip_E EXCEPT ![self] = defaultInitValue]
                        /\ host_E' = [host_E EXCEPT ![self] = defaultInitValue]
                        /\ indecies_' = [indecies_ EXCEPT ![self] = defaultInitValue]
                        /\ pc' = [pc EXCEPT ![self] = "evtSeqVStart"]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, SendQueue, RcvQueue, MAX, 
                                        Marker1, Marker2, CmdConnect, 
                                        CmdDisconnect, PortSpaceFull, depth_, 
                                        host_, hidx_, host_idx_, pidx_, 
                                        port_idx_, depth_D, ip_, host_D, 
                                        connDomain_, cidx_, conn_, host_Co, 
                                        ip_C, hidx_C, host_idx_C, pidx_C, 
                                        port_idx_C, host_Dis, ip_Di, 
                                        connDomain_D, cidx_D, conn_D, host, ip, 
                                        connDomain_Di, cidx_Di, conn_Di, 
                                        depth_P, pkt_, ipkt_, entry_, conn_P, 
                                        hostMarker_, ip_idx_, ipidx_, ip_P, 
                                        host_P, pkt_P, ipkt_P, entry_P, 
                                        conn_Pu, hostMarker_P, ip_idx_P, 
                                        ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                        dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                        daddr_, hostidx_, hidx_P, otherEntry_, 
                                        i_, indicies_, portDomain_, 
                                        sourcePort_, destPort_, new_sport_, 
                                        depth_Pr, pkt_Pri, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth, i_Ev, 
                                        j, ip_Ev, host_Ev, indecies, i_C, i, 
                                        aa >>

pubtoprivVStart(self) == /\ pc[self] = "pubtoprivVStart"
                         /\ IF Len(SendQueue) > 0
                               THEN /\ pkt_' = [pkt_ EXCEPT ![self] = Head(SendQueue)]
                                    /\ PrintT(<<"PubToPrivMan - Len(SendQueue) > 0:", pkt_'[self], Connections, T>>)
                                    /\ SendQueue' = Tail(SendQueue)
                                    /\ IF Len(T) > 0
                                          THEN /\ PrintT(<<"PubToPrivMan - Len(T) > 0:">>)
                                               /\ entry_' = [entry_ EXCEPT ![self] = SelectSeq(T, LAMBDA e: e.reply.saddr=pkt_'[self].saddr /\
                                                                                                            e.reply.sport=pkt_'[self].sport /\
                                                                                                            e.reply.daddr=pkt_'[self].daddr /\
                                                                                                            e.reply.dport=pkt_'[self].dport)]
                                               /\ IF entry_'[self]=defaultInitValue
                                                     THEN /\ pc' = [pc EXCEPT ![self] = "pubtirprivVDE"]
                                                     ELSE /\ pc' = [pc EXCEPT ![self] = "pubtoprivEEmpty"]
                                          ELSE /\ pc' = [pc EXCEPT ![self] = "pubtopriVvRet"]
                                               /\ UNCHANGED entry_
                               ELSE /\ pc' = [pc EXCEPT ![self] = "pubtopriVvRet"]
                                    /\ UNCHANGED << SendQueue, pkt_, entry_ >>
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                         Connections, RcvQueue, MAX, Marker1, 
                                         Marker2, CmdConnect, CmdDisconnect, 
                                         PortSpaceFull, stack, depth_, host_, 
                                         hidx_, host_idx_, pidx_, port_idx_, 
                                         depth_D, ip_, host_D, connDomain_, 
                                         cidx_, conn_, host_Co, ip_C, hidx_C, 
                                         host_idx_C, pidx_C, port_idx_C, 
                                         host_Dis, ip_Di, connDomain_D, cidx_D, 
                                         conn_D, host, ip, connDomain_Di, 
                                         cidx_Di, conn_Di, depth_P, ipkt_, 
                                         conn_P, hostMarker_, ip_idx_, ipidx_, 
                                         ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, pkt_Pri, conn_Pr, 
                                         hostMarker_Pri, daddr_P, hostidx_P, 
                                         hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth_E, i_E, j_, 
                                         ip_E, host_E, indecies_, depth, i_Ev, 
                                         j, ip_Ev, host_Ev, indecies, i_C, i, 
                                         aa >>

pubtoprivEEmpty(self) == /\ pc[self] = "pubtoprivEEmpty"
                         /\ IF Len(entry_[self]) <= 0
                               THEN /\ PrintT(<<"PubToPrivVuln - Empty Entry">>)
                                    /\ pc' = [pc EXCEPT ![self] = "pubtopriVvRet"]
                               ELSE /\ PrintT(<<"PubToPrivMan - Len(entry) > -0:", entry_[self], pkt_[self]>>)
                                    /\ pc' = [pc EXCEPT ![self] = "pubtoPrivElse_"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                         Connections, SendQueue, RcvQueue, MAX, 
                                         Marker1, Marker2, CmdConnect, 
                                         CmdDisconnect, PortSpaceFull, stack, 
                                         depth_, host_, hidx_, host_idx_, 
                                         pidx_, port_idx_, depth_D, ip_, 
                                         host_D, connDomain_, cidx_, conn_, 
                                         host_Co, ip_C, hidx_C, host_idx_C, 
                                         pidx_C, port_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, pkt_Pri, conn_Pr, 
                                         hostMarker_Pri, daddr_P, hostidx_P, 
                                         hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth_E, i_E, j_, 
                                         ip_E, host_E, indecies_, depth, i_Ev, 
                                         j, ip_Ev, host_Ev, indecies, i_C, i, 
                                         aa >>

pubtoPrivElse_(self) == /\ pc[self] = "pubtoPrivElse_"
                        /\ entry_' = [entry_ EXCEPT ![self] = Head(entry_[self])]
                        /\ IF entry_'[self].reply.dport=N
                              THEN /\ PrintT(<<"PubToPrivMan - PortShadow: ", entry_'[self], pkt_[self]>>)
                              ELSE /\ TRUE
                        /\ IF entry_'[self].host_marker/=pkt_[self].host_marker
                              THEN /\ PrintT(<<"PubToPrivMan - entry.host_marker/=pkt.host_marker:", entry_'[self], pkt_[self]>>)
                                   /\ IF pkt_[self].host_marker = H1
                                         THEN /\ Marker1' = entry_'[self].host_marker
                                              /\ UNCHANGED Marker2
                                         ELSE /\ Marker2' = entry_'[self].host_marker
                                              /\ UNCHANGED Marker1
                                   /\ PrintT(<<"PubToPrivMan-Eviction Error: pkt", pkt_[self], " entry", entry_'[self], "Connections:", Connections, "T: ", T>>)
                              ELSE /\ TRUE
                                   /\ UNCHANGED << Marker1, Marker2 >>
                        /\ conn_P' = [conn_P EXCEPT ![self] = SelectSeq(Connections, LAMBDA e: entry_'[self].orig.saddr = Head(e))]
                        /\ IF Len(conn_P'[self]) > 0
                              THEN /\ pc' = [pc EXCEPT ![self] = "pubtoprivVConngt1"]
                              ELSE /\ pc' = [pc EXCEPT ![self] = "pubtopriVvRet"]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, SendQueue, RcvQueue, MAX, 
                                        CmdConnect, CmdDisconnect, 
                                        PortSpaceFull, stack, depth_, host_, 
                                        hidx_, host_idx_, pidx_, port_idx_, 
                                        depth_D, ip_, host_D, connDomain_, 
                                        cidx_, conn_, host_Co, ip_C, hidx_C, 
                                        host_idx_C, pidx_C, port_idx_C, 
                                        host_Dis, ip_Di, connDomain_D, cidx_D, 
                                        conn_D, host, ip, connDomain_Di, 
                                        cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                        hostMarker_, ip_idx_, ipidx_, ip_P, 
                                        host_P, pkt_P, ipkt_P, entry_P, 
                                        conn_Pu, hostMarker_P, ip_idx_P, 
                                        ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                        dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                        daddr_, hostidx_, hidx_P, otherEntry_, 
                                        i_, indicies_, portDomain_, 
                                        sourcePort_, destPort_, new_sport_, 
                                        depth_Pr, pkt_Pri, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth_E, 
                                        i_E, j_, ip_E, host_E, indecies_, 
                                        depth, i_Ev, j, ip_Ev, host_Ev, 
                                        indecies, i_C, i, aa >>

pubtoprivVConngt1(self) == /\ pc[self] = "pubtoprivVConngt1"
                           /\ conn_P' = [conn_P EXCEPT ![self] = Head(conn_P[self])]
                           /\ pc' = [pc EXCEPT ![self] = "pubtoprivVConngt2"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, T, 
                                           FreeIPs, UsedIPs, Connections, 
                                           SendQueue, RcvQueue, MAX, Marker1, 
                                           Marker2, CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, stack, depth_, host_, 
                                           hidx_, host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           hostMarker_, ip_idx_, ipidx_, ip_P, 
                                           host_P, pkt_P, ipkt_P, entry_P, 
                                           conn_Pu, hostMarker_P, ip_idx_P, 
                                           ipidx_P, ip_Pu, host_Pu, conn, 
                                           sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

pubtoprivVConngt2(self) == /\ pc[self] = "pubtoprivVConngt2"
                           /\ hostMarker_' = [hostMarker_ EXCEPT ![self] = conn_P[self][2]]
                           /\ IF hostMarker_'[self] = H1
                                 THEN /\ IF entry_[self].host_marker = H2
                                            THEN /\ PortScanInv' = TRUE
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED PortScanInv
                                      /\ Marker1' = entry_[self].host_marker
                                      /\ UNCHANGED Marker2
                                 ELSE /\ IF entry_[self].host_marker = H1
                                            THEN /\ PortScanInv' = TRUE
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED PortScanInv
                                      /\ Marker2' = entry_[self].host_marker
                                      /\ UNCHANGED Marker1
                           /\ pc' = [pc EXCEPT ![self] = "pubtopriVvRet"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           MaxTableSize, hosts, FreeHosts, 
                                           UsedHosts, Ports, ExtraPorts, 
                                           ExtraExtraPorts, T, FreeIPs, 
                                           UsedIPs, Connections, SendQueue, 
                                           RcvQueue, MAX, CmdConnect, 
                                           CmdDisconnect, PortSpaceFull, stack, 
                                           depth_, host_, hidx_, host_idx_, 
                                           pidx_, port_idx_, depth_D, ip_, 
                                           host_D, connDomain_, cidx_, conn_, 
                                           host_Co, ip_C, hidx_C, host_idx_C, 
                                           pidx_C, port_idx_C, host_Dis, ip_Di, 
                                           connDomain_D, cidx_D, conn_D, host, 
                                           ip, connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, ip_idx_, ipidx_, ip_P, 
                                           host_P, pkt_P, ipkt_P, entry_P, 
                                           conn_Pu, hostMarker_P, ip_idx_P, 
                                           ipidx_P, ip_Pu, host_Pu, conn, 
                                           sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

pubtirprivVDE(self) == /\ pc[self] = "pubtirprivVDE"
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ pkt_' = [pkt_ EXCEPT ![self] = Head(stack[self]).pkt_]
                       /\ ipkt_' = [ipkt_ EXCEPT ![self] = Head(stack[self]).ipkt_]
                       /\ entry_' = [entry_ EXCEPT ![self] = Head(stack[self]).entry_]
                       /\ conn_P' = [conn_P EXCEPT ![self] = Head(stack[self]).conn_P]
                       /\ hostMarker_' = [hostMarker_ EXCEPT ![self] = Head(stack[self]).hostMarker_]
                       /\ ip_idx_' = [ip_idx_ EXCEPT ![self] = Head(stack[self]).ip_idx_]
                       /\ ipidx_' = [ipidx_ EXCEPT ![self] = Head(stack[self]).ipidx_]
                       /\ ip_P' = [ip_P EXCEPT ![self] = Head(stack[self]).ip_P]
                       /\ host_P' = [host_P EXCEPT ![self] = Head(stack[self]).host_P]
                       /\ depth_P' = [depth_P EXCEPT ![self] = Head(stack[self]).depth_P]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, depth_, 
                                       host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, pkt_P, 
                                       ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                       ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                       sport, dstAddr, dport, pkt_Pr, 
                                       hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                       otherEntry_, i_, indicies_, portDomain_, 
                                       sourcePort_, destPort_, new_sport_, 
                                       depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i_C, i, aa >>

pubtopriVvRet(self) == /\ pc[self] = "pubtopriVvRet"
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ pkt_' = [pkt_ EXCEPT ![self] = Head(stack[self]).pkt_]
                       /\ ipkt_' = [ipkt_ EXCEPT ![self] = Head(stack[self]).ipkt_]
                       /\ entry_' = [entry_ EXCEPT ![self] = Head(stack[self]).entry_]
                       /\ conn_P' = [conn_P EXCEPT ![self] = Head(stack[self]).conn_P]
                       /\ hostMarker_' = [hostMarker_ EXCEPT ![self] = Head(stack[self]).hostMarker_]
                       /\ ip_idx_' = [ip_idx_ EXCEPT ![self] = Head(stack[self]).ip_idx_]
                       /\ ipidx_' = [ipidx_ EXCEPT ![self] = Head(stack[self]).ipidx_]
                       /\ ip_P' = [ip_P EXCEPT ![self] = Head(stack[self]).ip_P]
                       /\ host_P' = [host_P EXCEPT ![self] = Head(stack[self]).host_P]
                       /\ depth_P' = [depth_P EXCEPT ![self] = Head(stack[self]).depth_P]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, depth_, 
                                       host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, pkt_P, 
                                       ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                       ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                       sport, dstAddr, dport, pkt_Pr, 
                                       hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                       otherEntry_, i_, indicies_, portDomain_, 
                                       sourcePort_, destPort_, new_sport_, 
                                       depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i_C, i, aa >>

PubToPrivVuln(self) == pubtoprivVEvt3(self) \/ pubtoprivVStart(self)
                          \/ pubtoprivEEmpty(self) \/ pubtoPrivElse_(self)
                          \/ pubtoprivVConngt1(self)
                          \/ pubtoprivVConngt2(self) \/ pubtirprivVDE(self)
                          \/ pubtopriVvRet(self)

pubtoprivManStart(self) == /\ pc[self] = "pubtoprivManStart"
                           /\ IF Len(SendQueue) > 0
                                 THEN /\ pkt_P' = [pkt_P EXCEPT ![self] = Head(SendQueue)]
                                      /\ PrintT(<<"PubToPrivMan - Len(SendQueue) > 0:", pkt_P'[self], Connections, T>>)
                                      /\ SendQueue' = Tail(SendQueue)
                                      /\ IF Len(T) > 0
                                            THEN /\ PrintT(<<"PubToPrivMan - Len(T) > 0:">>)
                                                 /\ entry_P' = [entry_P EXCEPT ![self] = SelectSeq(T, LAMBDA e: e.reply.saddr=pkt_P'[self].saddr /\
                                                                                                                e.reply.sport=pkt_P'[self].sport /\
                                                                                                                e.reply.daddr=pkt_P'[self].daddr /\
                                                                                                                e.reply.dport=pkt_P'[self].dport)]
                                                 /\ IF Len(entry_P'[self]) <= 0
                                                       THEN /\ Assert((FALSE), 
                                                                      "Failure of assertion at line 298, column 9.")
                                                            /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet_"]
                                                       ELSE /\ PrintT(<<"PubToPrivMan - Len(entry) > -0:", entry_P'[self], pkt_P'[self]>>)
                                                            /\ pc' = [pc EXCEPT ![self] = "pubtoPrivElse_P"]
                                            ELSE /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet_"]
                                                 /\ UNCHANGED entry_P
                                 ELSE /\ PrintT(<<"PubToPrivMan - Else Len(SendQueue) <= 0">>)
                                      /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet_"]
                                      /\ UNCHANGED << SendQueue, pkt_P, 
                                                      entry_P >>
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, T, 
                                           FreeIPs, UsedIPs, Connections, 
                                           RcvQueue, MAX, Marker1, Marker2, 
                                           CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, stack, depth_, host_, 
                                           hidx_, host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, ipkt_P, 
                                           conn_Pu, hostMarker_P, ip_idx_P, 
                                           ipidx_P, ip_Pu, host_Pu, conn, 
                                           sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

pubtoPrivElse_P(self) == /\ pc[self] = "pubtoPrivElse_P"
                         /\ entry_P' = [entry_P EXCEPT ![self] = Head(entry_P[self])]
                         /\ IF entry_P'[self].reply.dport=N
                               THEN /\ PrintT(<<"PubToPrivMan - PortShadow: ", entry_P'[self], pkt_P[self]>>)
                               ELSE /\ TRUE
                         /\ IF entry_P'[self].host_marker/=pkt_P[self].host_marker
                               THEN /\ PrintT(<<"PubToPrivMan - entry.host_marker/=pkt.host_marker:", entry_P'[self], pkt_P[self]>>)
                                    /\ IF pkt_P[self].host_marker = H1
                                          THEN /\ Marker1' = entry_P'[self].host_marker
                                               /\ IF entry_P'[self].host_marker = H2
                                                     THEN /\ EvictionReroute' = TRUE
                                                     ELSE /\ TRUE
                                                          /\ UNCHANGED EvictionReroute
                                               /\ UNCHANGED Marker2
                                          ELSE /\ Marker2' = entry_P'[self].host_marker
                                               /\ IF entry_P'[self].host_marker = H1
                                                     THEN /\ EvictionReroute' = TRUE
                                                     ELSE /\ TRUE
                                                          /\ UNCHANGED EvictionReroute
                                               /\ UNCHANGED Marker1
                                    /\ PrintT(<<"PubToPrivMan - Eviction Error: pkt", pkt_P[self], " entry", entry_P'[self], "Connections:", Connections, "T: ", T>>)
                               ELSE /\ TRUE
                                    /\ UNCHANGED << EvictionReroute, Marker1, 
                                                    Marker2 >>
                         /\ conn_Pu' = [conn_Pu EXCEPT ![self] = SelectSeq(Connections, LAMBDA e: entry_P'[self].orig.saddr = Head(e))]
                         /\ IF Len(conn_Pu'[self]) > 0
                               THEN /\ pc' = [pc EXCEPT ![self] = "pubtoprivConngt1_"]
                               ELSE /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet_"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         PortScanInv, MaxTableSize, hosts, 
                                         FreeHosts, UsedHosts, Ports, 
                                         ExtraPorts, ExtraExtraPorts, T, 
                                         FreeIPs, UsedIPs, Connections, 
                                         SendQueue, RcvQueue, MAX, CmdConnect, 
                                         CmdDisconnect, PortSpaceFull, stack, 
                                         depth_, host_, hidx_, host_idx_, 
                                         pidx_, port_idx_, depth_D, ip_, 
                                         host_D, connDomain_, cidx_, conn_, 
                                         host_Co, ip_C, hidx_C, host_idx_C, 
                                         pidx_C, port_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, hostMarker_P, 
                                         ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                         conn, sport, dstAddr, dport, pkt_Pr, 
                                         hostMarker_Pr, daddr_, hostidx_, 
                                         hidx_P, otherEntry_, i_, indicies_, 
                                         portDomain_, sourcePort_, destPort_, 
                                         new_sport_, depth_Pr, pkt_Pri, 
                                         conn_Pr, hostMarker_Pri, daddr_P, 
                                         hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth_E, i_E, j_, 
                                         ip_E, host_E, indecies_, depth, i_Ev, 
                                         j, ip_Ev, host_Ev, indecies, i_C, i, 
                                         aa >>

pubtoprivConngt1_(self) == /\ pc[self] = "pubtoprivConngt1_"
                           /\ conn_Pu' = [conn_Pu EXCEPT ![self] = Head(conn_Pu[self])]
                           /\ pc' = [pc EXCEPT ![self] = "pubtoprivConngt2_"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, T, 
                                           FreeIPs, UsedIPs, Connections, 
                                           SendQueue, RcvQueue, MAX, Marker1, 
                                           Marker2, CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, stack, depth_, host_, 
                                           hidx_, host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, hostMarker_P, ip_idx_P, 
                                           ipidx_P, ip_Pu, host_Pu, conn, 
                                           sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

pubtoprivConngt2_(self) == /\ pc[self] = "pubtoprivConngt2_"
                           /\ hostMarker_P' = [hostMarker_P EXCEPT ![self] = conn_Pu[self][2]]
                           /\ IF hostMarker_P'[self] = H1
                                 THEN /\ IF entry_P[self].host_marker = H2
                                            THEN /\ PortScanInv' = TRUE
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED PortScanInv
                                      /\ Marker1' = entry_P[self].host_marker
                                      /\ UNCHANGED Marker2
                                 ELSE /\ IF entry_P[self].host_marker = H1
                                            THEN /\ PortScanInv' = TRUE
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED PortScanInv
                                      /\ Marker2' = entry_P[self].host_marker
                                      /\ UNCHANGED Marker1
                           /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet_"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           MaxTableSize, hosts, FreeHosts, 
                                           UsedHosts, Ports, ExtraPorts, 
                                           ExtraExtraPorts, T, FreeIPs, 
                                           UsedIPs, Connections, SendQueue, 
                                           RcvQueue, MAX, CmdConnect, 
                                           CmdDisconnect, PortSpaceFull, stack, 
                                           depth_, host_, hidx_, host_idx_, 
                                           pidx_, port_idx_, depth_D, ip_, 
                                           host_D, connDomain_, cidx_, conn_, 
                                           host_Co, ip_C, hidx_C, host_idx_C, 
                                           pidx_C, port_idx_C, host_Dis, ip_Di, 
                                           connDomain_D, cidx_D, conn_D, host, 
                                           ip, connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, conn_Pu, ip_idx_P, ipidx_P, 
                                           ip_Pu, host_Pu, conn, sport, 
                                           dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

pubtoprivRet_(self) == /\ pc[self] = "pubtoprivRet_"
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ pkt_P' = [pkt_P EXCEPT ![self] = Head(stack[self]).pkt_P]
                       /\ ipkt_P' = [ipkt_P EXCEPT ![self] = Head(stack[self]).ipkt_P]
                       /\ entry_P' = [entry_P EXCEPT ![self] = Head(stack[self]).entry_P]
                       /\ conn_Pu' = [conn_Pu EXCEPT ![self] = Head(stack[self]).conn_Pu]
                       /\ hostMarker_P' = [hostMarker_P EXCEPT ![self] = Head(stack[self]).hostMarker_P]
                       /\ ip_idx_P' = [ip_idx_P EXCEPT ![self] = Head(stack[self]).ip_idx_P]
                       /\ ipidx_P' = [ipidx_P EXCEPT ![self] = Head(stack[self]).ipidx_P]
                       /\ ip_Pu' = [ip_Pu EXCEPT ![self] = Head(stack[self]).ip_Pu]
                       /\ host_Pu' = [host_Pu EXCEPT ![self] = Head(stack[self]).host_Pu]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, depth_, 
                                       host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i_C, i, aa >>

PubToPrivMan(self) == pubtoprivManStart(self) \/ pubtoPrivElse_P(self)
                         \/ pubtoprivConngt1_(self)
                         \/ pubtoprivConngt2_(self) \/ pubtoprivRet_(self)

privtopubManStart_(self) == /\ pc[self] = "privtopubManStart_"
                            /\ IF Len (Connections) > 0
                                  THEN /\ sourcePort_' = [sourcePort_ EXCEPT ![self] = sport[self]]
                                       /\ pc' = [pc EXCEPT ![self] = "privtopubMan2Dport"]
                                  ELSE /\ pc' = [pc EXCEPT ![self] = "privtopubMan2Ret"]
                                       /\ UNCHANGED sourcePort_
                            /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                            Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                            Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                            Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                            EP1, PortMap1, EP2, PortMap2, 
                                            TableFull, EvictionReroute, 
                                            PortScanInv, MaxTableSize, hosts, 
                                            FreeHosts, UsedHosts, Ports, 
                                            ExtraPorts, ExtraExtraPorts, T, 
                                            FreeIPs, UsedIPs, Connections, 
                                            SendQueue, RcvQueue, MAX, Marker1, 
                                            Marker2, CmdConnect, CmdDisconnect, 
                                            PortSpaceFull, stack, depth_, 
                                            host_, hidx_, host_idx_, pidx_, 
                                            port_idx_, depth_D, ip_, host_D, 
                                            connDomain_, cidx_, conn_, host_Co, 
                                            ip_C, hidx_C, host_idx_C, pidx_C, 
                                            port_idx_C, host_Dis, ip_Di, 
                                            connDomain_D, cidx_D, conn_D, host, 
                                            ip, connDomain_Di, cidx_Di, 
                                            conn_Di, depth_P, pkt_, ipkt_, 
                                            entry_, conn_P, hostMarker_, 
                                            ip_idx_, ipidx_, ip_P, host_P, 
                                            pkt_P, ipkt_P, entry_P, conn_Pu, 
                                            hostMarker_P, ip_idx_P, ipidx_P, 
                                            ip_Pu, host_Pu, conn, sport, 
                                            dstAddr, dport, pkt_Pr, 
                                            hostMarker_Pr, daddr_, hostidx_, 
                                            hidx_P, otherEntry_, i_, indicies_, 
                                            portDomain_, destPort_, new_sport_, 
                                            depth_Pr, pkt_Pri, conn_Pr, 
                                            hostMarker_Pri, daddr_P, hostidx_P, 
                                            hidx_Pr, otherEntry_P, i_P, 
                                            indicies_P, portDomain_P, 
                                            sourcePort_P, destPort_P, 
                                            new_sport_P, pkt_Priv, conn_Pri, 
                                            hostMarker_Priv, daddr_Pr, 
                                            hostidx_Pr, hidx_Pri, 
                                            otherEntry_Pr, i_Pr, indicies_Pr, 
                                            portDomain_Pr, sourcePort_Pr, 
                                            destPort_Pr, new_sport_Pr, depth_C, 
                                            host_C, hidx_Co, host_idx, pidx, 
                                            port_idx, depth_Di, ip_D, host_Di, 
                                            connDomain, cidx, conn_Dis, 
                                            depth_Pu, pkt_Pu, ipkt, entry, 
                                            conn_Pub, hostMarker_Pu, ip_idx, 
                                            ipidx, ip_Pub, host_Pub, depth_Pri, 
                                            pkt, conn_Priv, hostMarker, daddr, 
                                            hostidx, hidx, otherEntry, i_Pri, 
                                            indicies, portDomain, sourcePort, 
                                            destPort, new_sport, good, depth_E, 
                                            i_E, j_, ip_E, host_E, indecies_, 
                                            depth, i_Ev, j, ip_Ev, host_Ev, 
                                            indecies, i_C, i, aa >>

privtopubMan2Dport(self) == /\ pc[self] = "privtopubMan2Dport"
                            /\ destPort_' = [destPort_ EXCEPT ![self] = dport[self]]
                            /\ daddr_' = [daddr_ EXCEPT ![self] = dstAddr[self]]
                            /\ PrintT(<<"PrivToPub - Conn: ", conn[self]>>)
                            /\ hostMarker_Pr' = [hostMarker_Pr EXCEPT ![self] = Head(Tail(conn[self]))]
                            /\ pkt_Pr' = [pkt_Pr EXCEPT ![self] = [saddr |-> Head(conn[self]), sport |-> sourcePort_[self],
                                                                   daddr |-> daddr_'[self], dport |-> destPort_'[self],
                                                                   host_marker |-> hostMarker_Pr'[self]
                                                                  ]]
                            /\ PrintT(<<"PrivToPubMan - pkt: ", conn[self], pkt_Pr'[self]>>)
                            /\ entry' = [entry EXCEPT ![self] = [host_marker |-> hostMarker_Pr'[self],
                                                                 orig |-> [saddr |-> pkt_Pr'[self].saddr, sport |-> pkt_Pr'[self].sport,
                                                                           daddr |-> pkt_Pr'[self].daddr, dport |-> pkt_Pr'[self].dport],
                                                                 reply |-> [saddr |-> pkt_Pr'[self].daddr, sport |-> pkt_Pr'[self].dport,
                                                                            daddr |-> N,  dport |-> pkt_Pr'[self].sport ]]]
                            /\ otherEntry_' = [otherEntry_ EXCEPT ![self] = SelectSeq(T, LAMBDA k: k.reply.saddr=pkt_Pr'[self].daddr /\ k.reply.sport=pkt_Pr'[self].dport /\
                                                                                                   k.reply.daddr=N /\ k.reply.dport=pkt_Pr'[self].sport)]
                            /\ PrintT(<<"PrivToPub - T", T, otherEntry_'[self], pkt_Pr'[self]>>)
                            /\ IF Len(otherEntry_'[self]) > 0
                                  THEN /\ T' = SelectSeq(T, LAMBDA e: ~(e.reply.saddr=pkt_Pr'[self].daddr /\ e.reply.sport=pkt_Pr'[self].dport /\
                                                                        e.reply.daddr=N /\ e.reply.dport=pkt_Pr'[self].sport) )
                                  ELSE /\ TRUE
                                       /\ T' = T
                            /\ pc' = [pc EXCEPT ![self] = "privtoPubMan2AddT"]
                            /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                            Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                            Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                            Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                            EP1, PortMap1, EP2, PortMap2, 
                                            TableFull, EvictionReroute, 
                                            PortScanInv, MaxTableSize, hosts, 
                                            FreeHosts, UsedHosts, Ports, 
                                            ExtraPorts, ExtraExtraPorts, 
                                            FreeIPs, UsedIPs, Connections, 
                                            SendQueue, RcvQueue, MAX, Marker1, 
                                            Marker2, CmdConnect, CmdDisconnect, 
                                            PortSpaceFull, stack, depth_, 
                                            host_, hidx_, host_idx_, pidx_, 
                                            port_idx_, depth_D, ip_, host_D, 
                                            connDomain_, cidx_, conn_, host_Co, 
                                            ip_C, hidx_C, host_idx_C, pidx_C, 
                                            port_idx_C, host_Dis, ip_Di, 
                                            connDomain_D, cidx_D, conn_D, host, 
                                            ip, connDomain_Di, cidx_Di, 
                                            conn_Di, depth_P, pkt_, ipkt_, 
                                            entry_, conn_P, hostMarker_, 
                                            ip_idx_, ipidx_, ip_P, host_P, 
                                            pkt_P, ipkt_P, entry_P, conn_Pu, 
                                            hostMarker_P, ip_idx_P, ipidx_P, 
                                            ip_Pu, host_Pu, conn, sport, 
                                            dstAddr, dport, hostidx_, hidx_P, 
                                            i_, indicies_, portDomain_, 
                                            sourcePort_, new_sport_, depth_Pr, 
                                            pkt_Pri, conn_Pr, hostMarker_Pri, 
                                            daddr_P, hostidx_P, hidx_Pr, 
                                            otherEntry_P, i_P, indicies_P, 
                                            portDomain_P, sourcePort_P, 
                                            destPort_P, new_sport_P, pkt_Priv, 
                                            conn_Pri, hostMarker_Priv, 
                                            daddr_Pr, hostidx_Pr, hidx_Pri, 
                                            otherEntry_Pr, i_Pr, indicies_Pr, 
                                            portDomain_Pr, sourcePort_Pr, 
                                            destPort_Pr, new_sport_Pr, depth_C, 
                                            host_C, hidx_Co, host_idx, pidx, 
                                            port_idx, depth_Di, ip_D, host_Di, 
                                            connDomain, cidx, conn_Dis, 
                                            depth_Pu, pkt_Pu, ipkt, conn_Pub, 
                                            hostMarker_Pu, ip_idx, ipidx, 
                                            ip_Pub, host_Pub, depth_Pri, pkt, 
                                            conn_Priv, hostMarker, daddr, 
                                            hostidx, hidx, otherEntry, i_Pri, 
                                            indicies, portDomain, sourcePort, 
                                            destPort, new_sport, good, depth_E, 
                                            i_E, j_, ip_E, host_E, indecies_, 
                                            depth, i_Ev, j, ip_Ev, host_Ev, 
                                            indecies, i_C, i, aa >>

privtoPubMan2AddT(self) == /\ pc[self] = "privtoPubMan2AddT"
                           /\ T' = Append(T, entry[self])
                           /\ pc' = [pc EXCEPT ![self] = "privtopubPkt_"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, 
                                           FreeIPs, UsedIPs, Connections, 
                                           SendQueue, RcvQueue, MAX, Marker1, 
                                           Marker2, CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, stack, depth_, host_, 
                                           hidx_, host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, conn_Pu, hostMarker_P, 
                                           ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                           conn, sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

privtopubPkt_(self) == /\ pc[self] = "privtopubPkt_"
                       /\ pkt_Pr' = [pkt_Pr EXCEPT ![self] = [saddr |->pkt_Pr[self].daddr, sport |-> pkt_Pr[self].dport,
                                                              daddr |-> N, dport |-> pkt_Pr[self].sport,
                                                              host_marker |-> hostMarker_Pr[self]]]
                       /\ SendQueue' = Append(SendQueue, pkt_Pr'[self])
                       /\ pc' = [pc EXCEPT ![self] = "privtopubMan2Ret"]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, RcvQueue, MAX, Marker1, 
                                       Marker2, CmdConnect, CmdDisconnect, 
                                       PortSpaceFull, stack, depth_, host_, 
                                       hidx_, host_idx_, pidx_, port_idx_, 
                                       depth_D, ip_, host_D, connDomain_, 
                                       cidx_, conn_, host_Co, ip_C, hidx_C, 
                                       host_idx_C, pidx_C, port_idx_C, 
                                       host_Dis, ip_Di, connDomain_D, cidx_D, 
                                       conn_D, host, ip, connDomain_Di, 
                                       cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                       entry_, conn_P, hostMarker_, ip_idx_, 
                                       ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                       entry_P, conn_Pu, hostMarker_P, 
                                       ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                       sport, dstAddr, dport, hostMarker_Pr, 
                                       daddr_, hostidx_, hidx_P, otherEntry_, 
                                       i_, indicies_, portDomain_, sourcePort_, 
                                       destPort_, new_sport_, depth_Pr, 
                                       pkt_Pri, conn_Pr, hostMarker_Pri, 
                                       daddr_P, hostidx_P, hidx_Pr, 
                                       otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i_C, i, aa >>

privtopubMan2Ret(self) == /\ pc[self] = "privtopubMan2Ret"
                          /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                          /\ pkt_Pr' = [pkt_Pr EXCEPT ![self] = Head(stack[self]).pkt_Pr]
                          /\ hostMarker_Pr' = [hostMarker_Pr EXCEPT ![self] = Head(stack[self]).hostMarker_Pr]
                          /\ daddr_' = [daddr_ EXCEPT ![self] = Head(stack[self]).daddr_]
                          /\ hostidx_' = [hostidx_ EXCEPT ![self] = Head(stack[self]).hostidx_]
                          /\ hidx_P' = [hidx_P EXCEPT ![self] = Head(stack[self]).hidx_P]
                          /\ otherEntry_' = [otherEntry_ EXCEPT ![self] = Head(stack[self]).otherEntry_]
                          /\ i_' = [i_ EXCEPT ![self] = Head(stack[self]).i_]
                          /\ indicies_' = [indicies_ EXCEPT ![self] = Head(stack[self]).indicies_]
                          /\ portDomain_' = [portDomain_ EXCEPT ![self] = Head(stack[self]).portDomain_]
                          /\ sourcePort_' = [sourcePort_ EXCEPT ![self] = Head(stack[self]).sourcePort_]
                          /\ destPort_' = [destPort_ EXCEPT ![self] = Head(stack[self]).destPort_]
                          /\ new_sport_' = [new_sport_ EXCEPT ![self] = Head(stack[self]).new_sport_]
                          /\ conn' = [conn EXCEPT ![self] = Head(stack[self]).conn]
                          /\ sport' = [sport EXCEPT ![self] = Head(stack[self]).sport]
                          /\ dstAddr' = [dstAddr EXCEPT ![self] = Head(stack[self]).dstAddr]
                          /\ dport' = [dport EXCEPT ![self] = Head(stack[self]).dport]
                          /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          FreeHosts, UsedHosts, Ports, 
                                          ExtraPorts, ExtraExtraPorts, T, 
                                          FreeIPs, UsedIPs, Connections, 
                                          SendQueue, RcvQueue, MAX, Marker1, 
                                          Marker2, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, depth_, host_, hidx_, 
                                          host_idx_, pidx_, port_idx_, depth_D, 
                                          ip_, host_D, connDomain_, cidx_, 
                                          conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, depth_Pr, 
                                          pkt_Pri, conn_Pr, hostMarker_Pri, 
                                          daddr_P, hostidx_P, hidx_Pr, 
                                          otherEntry_P, i_P, indicies_P, 
                                          portDomain_P, sourcePort_P, 
                                          destPort_P, new_sport_P, pkt_Priv, 
                                          conn_Pri, hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, conn_Pub, hostMarker_Pu, 
                                          ip_idx, ipidx, ip_Pub, host_Pub, 
                                          depth_Pri, pkt, conn_Priv, 
                                          hostMarker, daddr, hostidx, hidx, 
                                          otherEntry, i_Pri, indicies, 
                                          portDomain, sourcePort, destPort, 
                                          new_sport, good, depth_E, i_E, j_, 
                                          ip_E, host_E, indecies_, depth, i_Ev, 
                                          j, ip_Ev, host_Ev, indecies, i_C, i, 
                                          aa >>

PrivToPubMan2(self) == privtopubManStart_(self) \/ privtopubMan2Dport(self)
                          \/ privtoPubMan2AddT(self) \/ privtopubPkt_(self)
                          \/ privtopubMan2Ret(self)

privtopubV3(self) == /\ pc[self] = "privtopubV3"
                     /\ /\ depth_E' = [depth_E EXCEPT ![self] = depth_Pr[self]]
                        /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequenceVuln",
                                                                 pc        |->  "privtopubManStart_P",
                                                                 i_E       |->  i_E[self],
                                                                 j_        |->  j_[self],
                                                                 ip_E      |->  ip_E[self],
                                                                 host_E    |->  host_E[self],
                                                                 indecies_ |->  indecies_[self],
                                                                 depth_E   |->  depth_E[self] ] >>
                                                             \o stack[self]]
                     /\ i_E' = [i_E EXCEPT ![self] = defaultInitValue]
                     /\ j_' = [j_ EXCEPT ![self] = defaultInitValue]
                     /\ ip_E' = [ip_E EXCEPT ![self] = defaultInitValue]
                     /\ host_E' = [host_E EXCEPT ![self] = defaultInitValue]
                     /\ indecies_' = [indecies_ EXCEPT ![self] = defaultInitValue]
                     /\ pc' = [pc EXCEPT ![self] = "evtSeqVStart"]
                     /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                     Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, 
                                     Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, 
                                     H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                     PortMap2, TableFull, EvictionReroute, 
                                     PortScanInv, MaxTableSize, hosts, 
                                     FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                     ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                     Connections, SendQueue, RcvQueue, MAX, 
                                     Marker1, Marker2, CmdConnect, 
                                     CmdDisconnect, PortSpaceFull, depth_, 
                                     host_, hidx_, host_idx_, pidx_, port_idx_, 
                                     depth_D, ip_, host_D, connDomain_, cidx_, 
                                     conn_, host_Co, ip_C, hidx_C, host_idx_C, 
                                     pidx_C, port_idx_C, host_Dis, ip_Di, 
                                     connDomain_D, cidx_D, conn_D, host, ip, 
                                     connDomain_Di, cidx_Di, conn_Di, depth_P, 
                                     pkt_, ipkt_, entry_, conn_P, hostMarker_, 
                                     ip_idx_, ipidx_, ip_P, host_P, pkt_P, 
                                     ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                     ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                     sport, dstAddr, dport, pkt_Pr, 
                                     hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                     otherEntry_, i_, indicies_, portDomain_, 
                                     sourcePort_, destPort_, new_sport_, 
                                     depth_Pr, pkt_Pri, conn_Pr, 
                                     hostMarker_Pri, daddr_P, hostidx_P, 
                                     hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                     portDomain_P, sourcePort_P, destPort_P, 
                                     new_sport_P, pkt_Priv, conn_Pri, 
                                     hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                     hidx_Pri, otherEntry_Pr, i_Pr, 
                                     indicies_Pr, portDomain_Pr, sourcePort_Pr, 
                                     destPort_Pr, new_sport_Pr, depth_C, 
                                     host_C, hidx_Co, host_idx, pidx, port_idx, 
                                     depth_Di, ip_D, host_Di, connDomain, cidx, 
                                     conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                     conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                     ip_Pub, host_Pub, depth_Pri, pkt, 
                                     conn_Priv, hostMarker, daddr, hostidx, 
                                     hidx, otherEntry, i_Pri, indicies, 
                                     portDomain, sourcePort, destPort, 
                                     new_sport, good, depth, i_Ev, j, ip_Ev, 
                                     host_Ev, indecies, i_C, i, aa >>

privtopubManStart_P(self) == /\ pc[self] = "privtopubManStart_P"
                             /\ IF Len (Connections) > 0
                                   THEN /\ indicies_P' = [indicies_P EXCEPT ![self] = DOMAIN Connections]
                                        /\ portDomain_P' = [portDomain_P EXCEPT ![self] = DOMAIN Ports]
                                        /\ sourcePort_P' = [sourcePort_P EXCEPT ![self] = CHOOSE pr \in portDomain_P'[self] : TRUE]
                                        /\ i_P' = [i_P EXCEPT ![self] = CHOOSE f \in indicies_P'[self] : TRUE]
                                        /\ PrintT(<<"PrivToPub - conn", indecies[self], conn_Pr[self], Connections>>)
                                        /\ pc' = [pc EXCEPT ![self] = "privtopubConn_"]
                                   ELSE /\ pc' = [pc EXCEPT ![self] = "privtopubRet_"]
                                        /\ UNCHANGED << i_P, indicies_P, 
                                                        portDomain_P, 
                                                        sourcePort_P >>
                             /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                             Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, 
                                             Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, 
                                             Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                             MaxPorts, EP1, PortMap1, EP2, 
                                             PortMap2, TableFull, 
                                             EvictionReroute, PortScanInv, 
                                             MaxTableSize, hosts, FreeHosts, 
                                             UsedHosts, Ports, ExtraPorts, 
                                             ExtraExtraPorts, T, FreeIPs, 
                                             UsedIPs, Connections, SendQueue, 
                                             RcvQueue, MAX, Marker1, Marker2, 
                                             CmdConnect, CmdDisconnect, 
                                             PortSpaceFull, stack, depth_, 
                                             host_, hidx_, host_idx_, pidx_, 
                                             port_idx_, depth_D, ip_, host_D, 
                                             connDomain_, cidx_, conn_, 
                                             host_Co, ip_C, hidx_C, host_idx_C, 
                                             pidx_C, port_idx_C, host_Dis, 
                                             ip_Di, connDomain_D, cidx_D, 
                                             conn_D, host, ip, connDomain_Di, 
                                             cidx_Di, conn_Di, depth_P, pkt_, 
                                             ipkt_, entry_, conn_P, 
                                             hostMarker_, ip_idx_, ipidx_, 
                                             ip_P, host_P, pkt_P, ipkt_P, 
                                             entry_P, conn_Pu, hostMarker_P, 
                                             ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                             conn, sport, dstAddr, dport, 
                                             pkt_Pr, hostMarker_Pr, daddr_, 
                                             hostidx_, hidx_P, otherEntry_, i_, 
                                             indicies_, portDomain_, 
                                             sourcePort_, destPort_, 
                                             new_sport_, depth_Pr, pkt_Pri, 
                                             conn_Pr, hostMarker_Pri, daddr_P, 
                                             hostidx_P, hidx_Pr, otherEntry_P, 
                                             destPort_P, new_sport_P, pkt_Priv, 
                                             conn_Pri, hostMarker_Priv, 
                                             daddr_Pr, hostidx_Pr, hidx_Pri, 
                                             otherEntry_Pr, i_Pr, indicies_Pr, 
                                             portDomain_Pr, sourcePort_Pr, 
                                             destPort_Pr, new_sport_Pr, 
                                             depth_C, host_C, hidx_Co, 
                                             host_idx, pidx, port_idx, 
                                             depth_Di, ip_D, host_Di, 
                                             connDomain, cidx, conn_Dis, 
                                             depth_Pu, pkt_Pu, ipkt, entry, 
                                             conn_Pub, hostMarker_Pu, ip_idx, 
                                             ipidx, ip_Pub, host_Pub, 
                                             depth_Pri, pkt, conn_Priv, 
                                             hostMarker, daddr, hostidx, hidx, 
                                             otherEntry, i_Pri, indicies, 
                                             portDomain, sourcePort, destPort, 
                                             new_sport, good, depth_E, i_E, j_, 
                                             ip_E, host_E, indecies_, depth, 
                                             i_Ev, j, ip_Ev, host_Ev, indecies, 
                                             i_C, i, aa >>

privtopubConn_(self) == /\ pc[self] = "privtopubConn_"
                        /\ conn_Pr' = [conn_Pr EXCEPT ![self] = Connections[i_P[self]]]
                        /\ sourcePort_P' = [sourcePort_P EXCEPT ![self] = Ports[sourcePort_P[self]]]
                        /\ portDomain_P' = [portDomain_P EXCEPT ![self] = DOMAIN Ports]
                        /\ destPort_P' = [destPort_P EXCEPT ![self] = CHOOSE h \in portDomain_P'[self] : TRUE]
                        /\ pc' = [pc EXCEPT ![self] = "privtopubDport_"]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, SendQueue, RcvQueue, MAX, 
                                        Marker1, Marker2, CmdConnect, 
                                        CmdDisconnect, PortSpaceFull, stack, 
                                        depth_, host_, hidx_, host_idx_, pidx_, 
                                        port_idx_, depth_D, ip_, host_D, 
                                        connDomain_, cidx_, conn_, host_Co, 
                                        ip_C, hidx_C, host_idx_C, pidx_C, 
                                        port_idx_C, host_Dis, ip_Di, 
                                        connDomain_D, cidx_D, conn_D, host, ip, 
                                        connDomain_Di, cidx_Di, conn_Di, 
                                        depth_P, pkt_, ipkt_, entry_, conn_P, 
                                        hostMarker_, ip_idx_, ipidx_, ip_P, 
                                        host_P, pkt_P, ipkt_P, entry_P, 
                                        conn_Pu, hostMarker_P, ip_idx_P, 
                                        ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                        dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                        daddr_, hostidx_, hidx_P, otherEntry_, 
                                        i_, indicies_, portDomain_, 
                                        sourcePort_, destPort_, new_sport_, 
                                        depth_Pr, pkt_Pri, hostMarker_Pri, 
                                        daddr_P, hostidx_P, hidx_Pr, 
                                        otherEntry_P, i_P, indicies_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth_E, 
                                        i_E, j_, ip_E, host_E, indecies_, 
                                        depth, i_Ev, j, ip_Ev, host_Ev, 
                                        indecies, i_C, i, aa >>

privtopubDport_(self) == /\ pc[self] = "privtopubDport_"
                         /\ destPort_P' = [destPort_P EXCEPT ![self] = Ports[destPort_P[self]]]
                         /\ hostidx_P' = [hostidx_P EXCEPT ![self] = DOMAIN hosts]
                         /\ hidx_Pr' = [hidx_Pr EXCEPT ![self] = CHOOSE hid \in hostidx_P'[self] : TRUE]
                         /\ daddr_P' = [daddr_P EXCEPT ![self] = hosts[hidx_Pr'[self]]]
                         /\ PrintT(<<"PrivToPubVuln - Conn: ", conn_Pr[self]>>)
                         /\ hostMarker_Pri' = [hostMarker_Pri EXCEPT ![self] = Head(Tail(conn_Pr[self]))]
                         /\ pkt_Pri' = [pkt_Pri EXCEPT ![self] = [saddr |-> Head(conn_Pr[self]), sport |-> sourcePort_P[self],
                                                                  daddr |-> daddr_P'[self], dport |-> destPort_P'[self],
                                                                  host_marker |-> hostMarker_Pri'[self]
                                                                 ]]
                         /\ PrintT(<<"PrivToPubMan - pkt: ", conn_Pr[self], pkt_Pri'[self]>>)
                         /\ entry' = [entry EXCEPT ![self] = [host_marker |-> hostMarker_Pri'[self],
                                                              orig |-> [saddr |-> pkt_Pri'[self].saddr, sport |-> pkt_Pri'[self].sport,
                                                                        daddr |-> pkt_Pri'[self].daddr, dport |-> pkt_Pri'[self].dport],
                                                              reply |-> [saddr |-> pkt_Pri'[self].daddr, sport |-> pkt_Pri'[self].dport,
                                                                         daddr |-> N,  dport |-> pkt_Pri'[self].sport ]]]
                         /\ otherEntry_P' = [otherEntry_P EXCEPT ![self] = SelectSeq(T, LAMBDA k: k.reply.saddr=pkt_Pri'[self].daddr /\ k.reply.sport=pkt_Pri'[self].dport /\
                                                                                                  k.reply.daddr=N /\ k.reply.dport=pkt_Pri'[self].sport /\ k.host_marker /= hostMarker_Pri'[self])]
                         /\ PrintT(<<"PrivToPub - T", T, otherEntry_P'[self], pkt_Pri'[self]>>)
                         /\ IF Len(otherEntry_P'[self]) > 0
                               THEN /\ T' = SelectSeq(T, LAMBDA e: ~(e.reply.saddr=pkt_Pri'[self].daddr /\ e.reply.sport=pkt_Pri'[self].dport /\
                                                                     e.reply.daddr=N /\ e.reply.dport=pkt_Pri'[self].sport) )
                               ELSE /\ TRUE
                                    /\ T' = T
                         /\ pc' = [pc EXCEPT ![self] = "privtoPubManAddT_"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, FreeIPs, UsedIPs, 
                                         Connections, SendQueue, RcvQueue, MAX, 
                                         Marker1, Marker2, CmdConnect, 
                                         CmdDisconnect, PortSpaceFull, stack, 
                                         depth_, host_, hidx_, host_idx_, 
                                         pidx_, port_idx_, depth_D, ip_, 
                                         host_D, connDomain_, cidx_, conn_, 
                                         host_Co, ip_C, hidx_C, host_idx_C, 
                                         pidx_C, port_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, conn_Pr, i_P, indicies_P, 
                                         portDomain_P, sourcePort_P, 
                                         new_sport_P, pkt_Priv, conn_Pri, 
                                         hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                         hidx_Pri, otherEntry_Pr, i_Pr, 
                                         indicies_Pr, portDomain_Pr, 
                                         sourcePort_Pr, destPort_Pr, 
                                         new_sport_Pr, depth_C, host_C, 
                                         hidx_Co, host_idx, pidx, port_idx, 
                                         depth_Di, ip_D, host_Di, connDomain, 
                                         cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                         ipkt, conn_Pub, hostMarker_Pu, ip_idx, 
                                         ipidx, ip_Pub, host_Pub, depth_Pri, 
                                         pkt, conn_Priv, hostMarker, daddr, 
                                         hostidx, hidx, otherEntry, i_Pri, 
                                         indicies, portDomain, sourcePort, 
                                         destPort, new_sport, good, depth_E, 
                                         i_E, j_, ip_E, host_E, indecies_, 
                                         depth, i_Ev, j, ip_Ev, host_Ev, 
                                         indecies, i_C, i, aa >>

privtoPubManAddT_(self) == /\ pc[self] = "privtoPubManAddT_"
                           /\ T' = Append(T, entry[self])
                           /\ IF Len(T') > MaxTableSize
                                 THEN /\ TableFull' = TRUE
                                 ELSE /\ TRUE
                                      /\ UNCHANGED TableFull
                           /\ pc' = [pc EXCEPT ![self] = "privtopubPkt_P"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           EvictionReroute, PortScanInv, 
                                           MaxTableSize, hosts, FreeHosts, 
                                           UsedHosts, Ports, ExtraPorts, 
                                           ExtraExtraPorts, FreeIPs, UsedIPs, 
                                           Connections, SendQueue, RcvQueue, 
                                           MAX, Marker1, Marker2, CmdConnect, 
                                           CmdDisconnect, PortSpaceFull, stack, 
                                           depth_, host_, hidx_, host_idx_, 
                                           pidx_, port_idx_, depth_D, ip_, 
                                           host_D, connDomain_, cidx_, conn_, 
                                           host_Co, ip_C, hidx_C, host_idx_C, 
                                           pidx_C, port_idx_C, host_Dis, ip_Di, 
                                           connDomain_D, cidx_D, conn_D, host, 
                                           ip, connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, conn_Pu, hostMarker_P, 
                                           ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                           conn, sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

privtopubPkt_P(self) == /\ pc[self] = "privtopubPkt_P"
                        /\ pkt_Pri' = [pkt_Pri EXCEPT ![self] = [saddr |->pkt_Pri[self].daddr, sport |-> pkt_Pri[self].dport,
                                                                 daddr |-> N, dport |-> pkt_Pri[self].sport,
                                                                 host_marker |-> hostMarker_Pri[self]]]
                        /\ SendQueue' = Append(SendQueue, pkt_Pri'[self])
                        /\ pc' = [pc EXCEPT ![self] = "privtopubRet_"]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, RcvQueue, MAX, Marker1, 
                                        Marker2, CmdConnect, CmdDisconnect, 
                                        PortSpaceFull, stack, depth_, host_, 
                                        hidx_, host_idx_, pidx_, port_idx_, 
                                        depth_D, ip_, host_D, connDomain_, 
                                        cidx_, conn_, host_Co, ip_C, hidx_C, 
                                        host_idx_C, pidx_C, port_idx_C, 
                                        host_Dis, ip_Di, connDomain_D, cidx_D, 
                                        conn_D, host, ip, connDomain_Di, 
                                        cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                        entry_, conn_P, hostMarker_, ip_idx_, 
                                        ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                        entry_P, conn_Pu, hostMarker_P, 
                                        ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                        conn, sport, dstAddr, dport, pkt_Pr, 
                                        hostMarker_Pr, daddr_, hostidx_, 
                                        hidx_P, otherEntry_, i_, indicies_, 
                                        portDomain_, sourcePort_, destPort_, 
                                        new_sport_, depth_Pr, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth_E, 
                                        i_E, j_, ip_E, host_E, indecies_, 
                                        depth, i_Ev, j, ip_Ev, host_Ev, 
                                        indecies, i_C, i, aa >>

privtopubRet_(self) == /\ pc[self] = "privtopubRet_"
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ pkt_Pri' = [pkt_Pri EXCEPT ![self] = Head(stack[self]).pkt_Pri]
                       /\ conn_Pr' = [conn_Pr EXCEPT ![self] = Head(stack[self]).conn_Pr]
                       /\ hostMarker_Pri' = [hostMarker_Pri EXCEPT ![self] = Head(stack[self]).hostMarker_Pri]
                       /\ daddr_P' = [daddr_P EXCEPT ![self] = Head(stack[self]).daddr_P]
                       /\ hostidx_P' = [hostidx_P EXCEPT ![self] = Head(stack[self]).hostidx_P]
                       /\ hidx_Pr' = [hidx_Pr EXCEPT ![self] = Head(stack[self]).hidx_Pr]
                       /\ otherEntry_P' = [otherEntry_P EXCEPT ![self] = Head(stack[self]).otherEntry_P]
                       /\ i_P' = [i_P EXCEPT ![self] = Head(stack[self]).i_P]
                       /\ indicies_P' = [indicies_P EXCEPT ![self] = Head(stack[self]).indicies_P]
                       /\ portDomain_P' = [portDomain_P EXCEPT ![self] = Head(stack[self]).portDomain_P]
                       /\ sourcePort_P' = [sourcePort_P EXCEPT ![self] = Head(stack[self]).sourcePort_P]
                       /\ destPort_P' = [destPort_P EXCEPT ![self] = Head(stack[self]).destPort_P]
                       /\ new_sport_P' = [new_sport_P EXCEPT ![self] = Head(stack[self]).new_sport_P]
                       /\ depth_Pr' = [depth_Pr EXCEPT ![self] = Head(stack[self]).depth_Pr]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, depth_, 
                                       host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i_C, i, aa >>

PrivToPubVuln(self) == privtopubV3(self) \/ privtopubManStart_P(self)
                          \/ privtopubConn_(self) \/ privtopubDport_(self)
                          \/ privtoPubManAddT_(self)
                          \/ privtopubPkt_P(self) \/ privtopubRet_(self)

privtopubManStart(self) == /\ pc[self] = "privtopubManStart"
                           /\ IF Len (Connections) > 0
                                 THEN /\ indicies_Pr' = [indicies_Pr EXCEPT ![self] = DOMAIN Connections]
                                      /\ portDomain_Pr' = [portDomain_Pr EXCEPT ![self] = DOMAIN Ports]
                                      /\ sourcePort_Pr' = [sourcePort_Pr EXCEPT ![self] = CHOOSE pr \in portDomain_Pr'[self] : TRUE]
                                      /\ i_Pr' = [i_Pr EXCEPT ![self] = CHOOSE f \in indicies_Pr'[self] : TRUE]
                                      /\ pc' = [pc EXCEPT ![self] = "privtopubManConn"]
                                 ELSE /\ pc' = [pc EXCEPT ![self] = "privtopubRet_P"]
                                      /\ UNCHANGED << i_Pr, indicies_Pr, 
                                                      portDomain_Pr, 
                                                      sourcePort_Pr >>
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, T, 
                                           FreeIPs, UsedIPs, Connections, 
                                           SendQueue, RcvQueue, MAX, Marker1, 
                                           Marker2, CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, stack, depth_, host_, 
                                           hidx_, host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, conn_Pu, hostMarker_P, 
                                           ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                           conn, sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           destPort_Pr, new_sport_Pr, depth_C, 
                                           host_C, hidx_Co, host_idx, pidx, 
                                           port_idx, depth_Di, ip_D, host_Di, 
                                           connDomain, cidx, conn_Dis, 
                                           depth_Pu, pkt_Pu, ipkt, entry, 
                                           conn_Pub, hostMarker_Pu, ip_idx, 
                                           ipidx, ip_Pub, host_Pub, depth_Pri, 
                                           pkt, conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

privtopubManConn(self) == /\ pc[self] = "privtopubManConn"
                          /\ conn_Pri' = [conn_Pri EXCEPT ![self] = Connections[i_Pr[self]]]
                          /\ sourcePort_Pr' = [sourcePort_Pr EXCEPT ![self] = B]
                          /\ portDomain_Pr' = [portDomain_Pr EXCEPT ![self] = DOMAIN Ports]
                          /\ destPort_Pr' = [destPort_Pr EXCEPT ![self] = CHOOSE h \in portDomain_Pr'[self] : TRUE]
                          /\ pc' = [pc EXCEPT ![self] = "privtopubManDport"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          FreeHosts, UsedHosts, Ports, 
                                          ExtraPorts, ExtraExtraPorts, T, 
                                          FreeIPs, UsedIPs, Connections, 
                                          SendQueue, RcvQueue, MAX, Marker1, 
                                          Marker2, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, stack, depth_, host_, 
                                          hidx_, host_idx_, pidx_, port_idx_, 
                                          depth_D, ip_, host_D, connDomain_, 
                                          cidx_, conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, new_sport_Pr, 
                                          depth_C, host_C, hidx_Co, host_idx, 
                                          pidx, port_idx, depth_Di, ip_D, 
                                          host_Di, connDomain, cidx, conn_Dis, 
                                          depth_Pu, pkt_Pu, ipkt, entry, 
                                          conn_Pub, hostMarker_Pu, ip_idx, 
                                          ipidx, ip_Pub, host_Pub, depth_Pri, 
                                          pkt, conn_Priv, hostMarker, daddr, 
                                          hostidx, hidx, otherEntry, i_Pri, 
                                          indicies, portDomain, sourcePort, 
                                          destPort, new_sport, good, depth_E, 
                                          i_E, j_, ip_E, host_E, indecies_, 
                                          depth, i_Ev, j, ip_Ev, host_Ev, 
                                          indecies, i_C, i, aa >>

privtopubManDport(self) == /\ pc[self] = "privtopubManDport"
                           /\ destPort_Pr' = [destPort_Pr EXCEPT ![self] = C]
                           /\ hostidx_Pr' = [hostidx_Pr EXCEPT ![self] = DOMAIN hosts]
                           /\ hidx_Pri' = [hidx_Pri EXCEPT ![self] = CHOOSE hid \in hostidx_Pr'[self] : TRUE]
                           /\ daddr_Pr' = [daddr_Pr EXCEPT ![self] = C]
                           /\ PrintT(<<"PrivToPubMan - Len(connections) > 0: ", indicies_Pr[self], conn_Pri[self], Connections>>)
                           /\ hostMarker_Priv' = [hostMarker_Priv EXCEPT ![self] = Head(Tail(conn_Pri[self]))]
                           /\ pkt_Priv' = [pkt_Priv EXCEPT ![self] = [saddr |-> Head(conn_Pri[self]), sport |-> sourcePort_Pr[self],
                                                                      daddr |-> daddr_Pr'[self], dport |-> destPort_Pr'[self],
                                                                      host_marker |-> hostMarker_Priv'[self]
                                                                     ]]
                           /\ PrintT(<<"PrivToPubMan - conn, pkt: ", conn_Pri[self], pkt_Priv'[self]>>)
                           /\ entry' = [entry EXCEPT ![self] = [host_marker |-> hostMarker_Priv'[self],
                                                                orig |-> [saddr |-> pkt_Priv'[self].saddr, sport |-> pkt_Priv'[self].sport,
                                                                          daddr |-> pkt_Priv'[self].daddr, dport |-> pkt_Priv'[self].dport],
                                                                reply |-> [saddr |-> pkt_Priv'[self].daddr, sport |-> pkt_Priv'[self].dport,
                                                                           daddr |-> N,  dport |-> pkt_Priv'[self].sport ]]]
                           /\ otherEntry_Pr' = [otherEntry_Pr EXCEPT ![self] = SelectSeq(T, LAMBDA k: k.reply.saddr=pkt_Priv'[self].daddr /\ k.reply.sport=pkt_Priv'[self].dport /\
                                                                                                      k.reply.daddr=N /\ k.reply.dport=pkt_Priv'[self].sport)]
                           /\ PrintT(<<"PrivToPubMan - T", T, otherEntry_Pr'[self], pkt_Priv'[self]>>)
                           /\ IF Len(otherEntry_Pr'[self]) > 0
                                 THEN /\ T' = SelectSeq(T, LAMBDA e: ~(e.reply.saddr=pkt_Priv'[self].daddr /\ e.reply.sport=pkt_Priv'[self].dport /\
                                                                       e.reply.daddr=N /\ e.reply.dport=pkt_Priv'[self].sport) )
                                 ELSE /\ TRUE
                                      /\ T' = T
                           /\ pc' = [pc EXCEPT ![self] = "privtoPubManAddT"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, 
                                           FreeIPs, UsedIPs, Connections, 
                                           SendQueue, RcvQueue, MAX, Marker1, 
                                           Marker2, CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, stack, depth_, host_, 
                                           hidx_, host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, conn_Pu, hostMarker_P, 
                                           ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                           conn, sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, conn_Pri, i_Pr, 
                                           indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, new_sport_Pr, 
                                           depth_C, host_C, hidx_Co, host_idx, 
                                           pidx, port_idx, depth_Di, ip_D, 
                                           host_Di, connDomain, cidx, conn_Dis, 
                                           depth_Pu, pkt_Pu, ipkt, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, i, aa >>

privtoPubManAddT(self) == /\ pc[self] = "privtoPubManAddT"
                          /\ T' = Append(T, entry[self])
                          /\ pc' = [pc EXCEPT ![self] = "privtopubPkt_Pr"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          FreeHosts, UsedHosts, Ports, 
                                          ExtraPorts, ExtraExtraPorts, FreeIPs, 
                                          UsedIPs, Connections, SendQueue, 
                                          RcvQueue, MAX, Marker1, Marker2, 
                                          CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, stack, depth_, host_, 
                                          hidx_, host_idx_, pidx_, port_idx_, 
                                          depth_D, ip_, host_D, connDomain_, 
                                          cidx_, conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, conn_Pub, hostMarker_Pu, 
                                          ip_idx, ipidx, ip_Pub, host_Pub, 
                                          depth_Pri, pkt, conn_Priv, 
                                          hostMarker, daddr, hostidx, hidx, 
                                          otherEntry, i_Pri, indicies, 
                                          portDomain, sourcePort, destPort, 
                                          new_sport, good, depth_E, i_E, j_, 
                                          ip_E, host_E, indecies_, depth, i_Ev, 
                                          j, ip_Ev, host_Ev, indecies, i_C, i, 
                                          aa >>

privtopubPkt_Pr(self) == /\ pc[self] = "privtopubPkt_Pr"
                         /\ pkt_Priv' = [pkt_Priv EXCEPT ![self] = [saddr |->pkt_Priv[self].daddr, sport |-> pkt_Priv[self].dport,
                                                                    daddr |-> N, dport |-> pkt_Priv[self].sport,
                                                                    host_marker |-> hostMarker_Priv[self]]]
                         /\ SendQueue' = Append(SendQueue, pkt_Priv'[self])
                         /\ pc' = [pc EXCEPT ![self] = "privtopubRet_P"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                         Connections, RcvQueue, MAX, Marker1, 
                                         Marker2, CmdConnect, CmdDisconnect, 
                                         PortSpaceFull, stack, depth_, host_, 
                                         hidx_, host_idx_, pidx_, port_idx_, 
                                         depth_D, ip_, host_D, connDomain_, 
                                         cidx_, conn_, host_Co, ip_C, hidx_C, 
                                         host_idx_C, pidx_C, port_idx_C, 
                                         host_Dis, ip_Di, connDomain_D, cidx_D, 
                                         conn_D, host, ip, connDomain_Di, 
                                         cidx_Di, conn_Di, depth_P, pkt_, 
                                         ipkt_, entry_, conn_P, hostMarker_, 
                                         ip_idx_, ipidx_, ip_P, host_P, pkt_P, 
                                         ipkt_P, entry_P, conn_Pu, 
                                         hostMarker_P, ip_idx_P, ipidx_P, 
                                         ip_Pu, host_Pu, conn, sport, dstAddr, 
                                         dport, pkt_Pr, hostMarker_Pr, daddr_, 
                                         hostidx_, hidx_P, otherEntry_, i_, 
                                         indicies_, portDomain_, sourcePort_, 
                                         destPort_, new_sport_, depth_Pr, 
                                         pkt_Pri, conn_Pr, hostMarker_Pri, 
                                         daddr_P, hostidx_P, hidx_Pr, 
                                         otherEntry_P, i_P, indicies_P, 
                                         portDomain_P, sourcePort_P, 
                                         destPort_P, new_sport_P, conn_Pri, 
                                         hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                         hidx_Pri, otherEntry_Pr, i_Pr, 
                                         indicies_Pr, portDomain_Pr, 
                                         sourcePort_Pr, destPort_Pr, 
                                         new_sport_Pr, depth_C, host_C, 
                                         hidx_Co, host_idx, pidx, port_idx, 
                                         depth_Di, ip_D, host_Di, connDomain, 
                                         cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                         ipkt, entry, conn_Pub, hostMarker_Pu, 
                                         ip_idx, ipidx, ip_Pub, host_Pub, 
                                         depth_Pri, pkt, conn_Priv, hostMarker, 
                                         daddr, hostidx, hidx, otherEntry, 
                                         i_Pri, indicies, portDomain, 
                                         sourcePort, destPort, new_sport, good, 
                                         depth_E, i_E, j_, ip_E, host_E, 
                                         indecies_, depth, i_Ev, j, ip_Ev, 
                                         host_Ev, indecies, i_C, i, aa >>

privtopubRet_P(self) == /\ pc[self] = "privtopubRet_P"
                        /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                        /\ pkt_Priv' = [pkt_Priv EXCEPT ![self] = Head(stack[self]).pkt_Priv]
                        /\ conn_Pri' = [conn_Pri EXCEPT ![self] = Head(stack[self]).conn_Pri]
                        /\ hostMarker_Priv' = [hostMarker_Priv EXCEPT ![self] = Head(stack[self]).hostMarker_Priv]
                        /\ daddr_Pr' = [daddr_Pr EXCEPT ![self] = Head(stack[self]).daddr_Pr]
                        /\ hostidx_Pr' = [hostidx_Pr EXCEPT ![self] = Head(stack[self]).hostidx_Pr]
                        /\ hidx_Pri' = [hidx_Pri EXCEPT ![self] = Head(stack[self]).hidx_Pri]
                        /\ otherEntry_Pr' = [otherEntry_Pr EXCEPT ![self] = Head(stack[self]).otherEntry_Pr]
                        /\ i_Pr' = [i_Pr EXCEPT ![self] = Head(stack[self]).i_Pr]
                        /\ indicies_Pr' = [indicies_Pr EXCEPT ![self] = Head(stack[self]).indicies_Pr]
                        /\ portDomain_Pr' = [portDomain_Pr EXCEPT ![self] = Head(stack[self]).portDomain_Pr]
                        /\ sourcePort_Pr' = [sourcePort_Pr EXCEPT ![self] = Head(stack[self]).sourcePort_Pr]
                        /\ destPort_Pr' = [destPort_Pr EXCEPT ![self] = Head(stack[self]).destPort_Pr]
                        /\ new_sport_Pr' = [new_sport_Pr EXCEPT ![self] = Head(stack[self]).new_sport_Pr]
                        /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, SendQueue, RcvQueue, MAX, 
                                        Marker1, Marker2, CmdConnect, 
                                        CmdDisconnect, PortSpaceFull, depth_, 
                                        host_, hidx_, host_idx_, pidx_, 
                                        port_idx_, depth_D, ip_, host_D, 
                                        connDomain_, cidx_, conn_, host_Co, 
                                        ip_C, hidx_C, host_idx_C, pidx_C, 
                                        port_idx_C, host_Dis, ip_Di, 
                                        connDomain_D, cidx_D, conn_D, host, ip, 
                                        connDomain_Di, cidx_Di, conn_Di, 
                                        depth_P, pkt_, ipkt_, entry_, conn_P, 
                                        hostMarker_, ip_idx_, ipidx_, ip_P, 
                                        host_P, pkt_P, ipkt_P, entry_P, 
                                        conn_Pu, hostMarker_P, ip_idx_P, 
                                        ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                        dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                        daddr_, hostidx_, hidx_P, otherEntry_, 
                                        i_, indicies_, portDomain_, 
                                        sourcePort_, destPort_, new_sport_, 
                                        depth_Pr, pkt_Pri, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth_E, 
                                        i_E, j_, ip_E, host_E, indecies_, 
                                        depth, i_Ev, j, ip_Ev, host_Ev, 
                                        indecies, i_C, i, aa >>

PrivToPubMan(self) == privtopubManStart(self) \/ privtopubManConn(self)
                         \/ privtopubManDport(self)
                         \/ privtoPubManAddT(self) \/ privtopubPkt_Pr(self)
                         \/ privtopubRet_P(self)

connectStart(self) == /\ pc[self] = "connectStart"
                      /\ /\ depth' = [depth EXCEPT ![self] = depth_C[self]]
                         /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequence",
                                                                  pc        |->  "connectIf",
                                                                  i_Ev      |->  i_Ev[self],
                                                                  j         |->  j[self],
                                                                  ip_Ev     |->  ip_Ev[self],
                                                                  host_Ev   |->  host_Ev[self],
                                                                  indecies  |->  indecies[self],
                                                                  depth     |->  depth[self] ] >>
                                                              \o stack[self]]
                      /\ i_Ev' = [i_Ev EXCEPT ![self] = defaultInitValue]
                      /\ j' = [j EXCEPT ![self] = defaultInitValue]
                      /\ ip_Ev' = [ip_Ev EXCEPT ![self] = defaultInitValue]
                      /\ host_Ev' = [host_Ev EXCEPT ![self] = defaultInitValue]
                      /\ indecies' = [indecies EXCEPT ![self] = defaultInitValue]
                      /\ pc' = [pc EXCEPT ![self] = "evtSeqStart"]
                      /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                      Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                      Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                      Zz, H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                      PortMap2, TableFull, EvictionReroute, 
                                      PortScanInv, MaxTableSize, hosts, 
                                      FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                      ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                      Connections, SendQueue, RcvQueue, MAX, 
                                      Marker1, Marker2, CmdConnect, 
                                      CmdDisconnect, PortSpaceFull, depth_, 
                                      host_, hidx_, host_idx_, pidx_, 
                                      port_idx_, depth_D, ip_, host_D, 
                                      connDomain_, cidx_, conn_, host_Co, ip_C, 
                                      hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                      host_Dis, ip_Di, connDomain_D, cidx_D, 
                                      conn_D, host, ip, connDomain_Di, cidx_Di, 
                                      conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                      conn_P, hostMarker_, ip_idx_, ipidx_, 
                                      ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                      conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                      ip_Pu, host_Pu, conn, sport, dstAddr, 
                                      dport, pkt_Pr, hostMarker_Pr, daddr_, 
                                      hostidx_, hidx_P, otherEntry_, i_, 
                                      indicies_, portDomain_, sourcePort_, 
                                      destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                      conn_Pr, hostMarker_Pri, daddr_P, 
                                      hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                      indicies_P, portDomain_P, sourcePort_P, 
                                      destPort_P, new_sport_P, pkt_Priv, 
                                      conn_Pri, hostMarker_Priv, daddr_Pr, 
                                      hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                      i_Pr, indicies_Pr, portDomain_Pr, 
                                      sourcePort_Pr, destPort_Pr, new_sport_Pr, 
                                      depth_C, host_C, hidx_Co, host_idx, pidx, 
                                      port_idx, depth_Di, ip_D, host_Di, 
                                      connDomain, cidx, conn_Dis, depth_Pu, 
                                      pkt_Pu, ipkt, entry, conn_Pub, 
                                      hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                      host_Pub, depth_Pri, pkt, conn_Priv, 
                                      hostMarker, daddr, hostidx, hidx, 
                                      otherEntry, i_Pri, indicies, portDomain, 
                                      sourcePort, destPort, new_sport, good, 
                                      depth_E, i_E, j_, ip_E, host_E, 
                                      indecies_, i_C, i, aa >>

connectIf(self) == /\ pc[self] = "connectIf"
                   /\ IF Len(FreeHosts) > 0
                         THEN /\ host_idx' = [host_idx EXCEPT ![self] = DOMAIN FreeHosts]
                              /\ hidx_Co' = [hidx_Co EXCEPT ![self] = CHOOSE h \in host_idx'[self] : TRUE]
                              /\ host_C' = [host_C EXCEPT ![self] = FreeHosts[hidx_Co'[self]]]
                              /\ FreeHosts' = SelectSeq(FreeHosts, LAMBDA a: a /= host_C'[self])
                              /\ UsedHosts' = Append(UsedHosts, host_C'[self])
                              /\ port_idx' = [port_idx EXCEPT ![self] = DOMAIN Ports]
                              /\ pidx' = [pidx EXCEPT ![self] = CHOOSE p \in port_idx'[self] : TRUE]
                              /\ pkt' = [pkt EXCEPT ![self] = [ saddr |-> host_C'[self], sport |-> Ports[pidx'[self]],
                                                                daddr |-> N,    dport |-> N,
                                                                cmd |-> CmdConnect,
                                                                host_marker |-> host_C'[self]]]
                              /\ SendQueue' = Append(SendQueue, pkt'[self])
                         ELSE /\ TRUE
                              /\ UNCHANGED << FreeHosts, UsedHosts, SendQueue, 
                                              host_C, hidx_Co, host_idx, pidx, 
                                              port_idx, pkt >>
                   /\ pc' = [pc EXCEPT ![self] = "connectRet"]
                   /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                   Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                   Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                   MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                   TableFull, EvictionReroute, PortScanInv, 
                                   MaxTableSize, hosts, Ports, ExtraPorts, 
                                   ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                   Connections, RcvQueue, MAX, Marker1, 
                                   Marker2, CmdConnect, CmdDisconnect, 
                                   PortSpaceFull, stack, depth_, host_, hidx_, 
                                   host_idx_, pidx_, port_idx_, depth_D, ip_, 
                                   host_D, connDomain_, cidx_, conn_, host_Co, 
                                   ip_C, hidx_C, host_idx_C, pidx_C, 
                                   port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                   cidx_D, conn_D, host, ip, connDomain_Di, 
                                   cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                   entry_, conn_P, hostMarker_, ip_idx_, 
                                   ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                   entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                   ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                   dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                   daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                   indicies_, portDomain_, sourcePort_, 
                                   destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                   conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, 
                                   hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                   portDomain_P, sourcePort_P, destPort_P, 
                                   new_sport_P, pkt_Priv, conn_Pri, 
                                   hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                   hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                   portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                   new_sport_Pr, depth_C, depth_Di, ip_D, 
                                   host_Di, connDomain, cidx, conn_Dis, 
                                   depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                   hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                   host_Pub, depth_Pri, conn_Priv, hostMarker, 
                                   daddr, hostidx, hidx, otherEntry, i_Pri, 
                                   indicies, portDomain, sourcePort, destPort, 
                                   new_sport, good, depth_E, i_E, j_, ip_E, 
                                   host_E, indecies_, depth, i_Ev, j, ip_Ev, 
                                   host_Ev, indecies, i_C, i, aa >>

connectRet(self) == /\ pc[self] = "connectRet"
                    /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                    /\ host_C' = [host_C EXCEPT ![self] = Head(stack[self]).host_C]
                    /\ hidx_Co' = [hidx_Co EXCEPT ![self] = Head(stack[self]).hidx_Co]
                    /\ host_idx' = [host_idx EXCEPT ![self] = Head(stack[self]).host_idx]
                    /\ pidx' = [pidx EXCEPT ![self] = Head(stack[self]).pidx]
                    /\ port_idx' = [port_idx EXCEPT ![self] = Head(stack[self]).port_idx]
                    /\ depth_C' = [depth_C EXCEPT ![self] = Head(stack[self]).depth_C]
                    /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_Di, ip_D, host_Di, 
                                    connDomain, cidx, conn_Dis, depth_Pu, 
                                    pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

Connect(self) == connectStart(self) \/ connectIf(self) \/ connectRet(self)

disconnectStart(self) == /\ pc[self] = "disconnectStart"
                         /\ /\ depth' = [depth EXCEPT ![self] = depth_Di[self]]
                            /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequence",
                                                                     pc        |->  "disconnectIf",
                                                                     i_Ev      |->  i_Ev[self],
                                                                     j         |->  j[self],
                                                                     ip_Ev     |->  ip_Ev[self],
                                                                     host_Ev   |->  host_Ev[self],
                                                                     indecies  |->  indecies[self],
                                                                     depth     |->  depth[self] ] >>
                                                                 \o stack[self]]
                         /\ i_Ev' = [i_Ev EXCEPT ![self] = defaultInitValue]
                         /\ j' = [j EXCEPT ![self] = defaultInitValue]
                         /\ ip_Ev' = [ip_Ev EXCEPT ![self] = defaultInitValue]
                         /\ host_Ev' = [host_Ev EXCEPT ![self] = defaultInitValue]
                         /\ indecies' = [indecies EXCEPT ![self] = defaultInitValue]
                         /\ pc' = [pc EXCEPT ![self] = "evtSeqStart"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                         Connections, SendQueue, RcvQueue, MAX, 
                                         Marker1, Marker2, CmdConnect, 
                                         CmdDisconnect, PortSpaceFull, depth_, 
                                         host_, hidx_, host_idx_, pidx_, 
                                         port_idx_, depth_D, ip_, host_D, 
                                         connDomain_, cidx_, conn_, host_Co, 
                                         ip_C, hidx_C, host_idx_C, pidx_C, 
                                         port_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, pkt_Pri, conn_Pr, 
                                         hostMarker_Pri, daddr_P, hostidx_P, 
                                         hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth_E, i_E, j_, 
                                         ip_E, host_E, indecies_, i_C, i, aa >>

disconnectIf(self) == /\ pc[self] = "disconnectIf"
                      /\ IF Len(Connections) > 0
                            THEN /\ connDomain' = [connDomain EXCEPT ![self] = DOMAIN Connections]
                                 /\ cidx' = [cidx EXCEPT ![self] = CHOOSE c \in connDomain'[self] : TRUE]
                                 /\ conn_Dis' = [conn_Dis EXCEPT ![self] = Connections[cidx'[self]]]
                                 /\ ip_D' = [ip_D EXCEPT ![self] = conn_Dis'[self][1]]
                                 /\ host_Di' = [host_Di EXCEPT ![self] = conn_Dis'[self][2]]
                                 /\ PrintT(<< "Disconnect- Before:", host_Di'[self], ip_D'[self], Connections>>)
                                 /\ Connections' = SelectSeq(Connections, LAMBDA cc: Head(cc)/=ip_D'[self])
                                 /\ UsedIPs' = SelectSeq(UsedIPs, LAMBDA ccc: ccc/=ip_D'[self])
                                 /\ FreeIPs' = Append(FreeIPs, ip_D'[self])
                                 /\ pc' = [pc EXCEPT ![self] = "disconnectPurgeOrphans1"]
                            ELSE /\ pc' = [pc EXCEPT ![self] = "disconnectRet"]
                                 /\ UNCHANGED << FreeIPs, UsedIPs, Connections, 
                                                 ip_D, host_Di, connDomain, 
                                                 cidx, conn_Dis >>
                      /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                      Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                      Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                      Zz, H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                      PortMap2, TableFull, EvictionReroute, 
                                      PortScanInv, MaxTableSize, hosts, 
                                      FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                      ExtraExtraPorts, T, SendQueue, RcvQueue, 
                                      MAX, Marker1, Marker2, CmdConnect, 
                                      CmdDisconnect, PortSpaceFull, stack, 
                                      depth_, host_, hidx_, host_idx_, pidx_, 
                                      port_idx_, depth_D, ip_, host_D, 
                                      connDomain_, cidx_, conn_, host_Co, ip_C, 
                                      hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                      host_Dis, ip_Di, connDomain_D, cidx_D, 
                                      conn_D, host, ip, connDomain_Di, cidx_Di, 
                                      conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                      conn_P, hostMarker_, ip_idx_, ipidx_, 
                                      ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                      conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                      ip_Pu, host_Pu, conn, sport, dstAddr, 
                                      dport, pkt_Pr, hostMarker_Pr, daddr_, 
                                      hostidx_, hidx_P, otherEntry_, i_, 
                                      indicies_, portDomain_, sourcePort_, 
                                      destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                      conn_Pr, hostMarker_Pri, daddr_P, 
                                      hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                      indicies_P, portDomain_P, sourcePort_P, 
                                      destPort_P, new_sport_P, pkt_Priv, 
                                      conn_Pri, hostMarker_Priv, daddr_Pr, 
                                      hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                      i_Pr, indicies_Pr, portDomain_Pr, 
                                      sourcePort_Pr, destPort_Pr, new_sport_Pr, 
                                      depth_C, host_C, hidx_Co, host_idx, pidx, 
                                      port_idx, depth_Di, depth_Pu, pkt_Pu, 
                                      ipkt, entry, conn_Pub, hostMarker_Pu, 
                                      ip_idx, ipidx, ip_Pub, host_Pub, 
                                      depth_Pri, pkt, conn_Priv, hostMarker, 
                                      daddr, hostidx, hidx, otherEntry, i_Pri, 
                                      indicies, portDomain, sourcePort, 
                                      destPort, new_sport, good, depth_E, i_E, 
                                      j_, ip_E, host_E, indecies_, depth, i_Ev, 
                                      j, ip_Ev, host_Ev, indecies, i_C, i, aa >>

disconnectPurgeOrphans1(self) == /\ pc[self] = "disconnectPurgeOrphans1"
                                 /\ T' = SelectSeq(T, LAMBDA e: e.orig.saddr /= ip_D[self])
                                 /\ pc' = [pc EXCEPT ![self] = "disconnectPurgeOrphans2"]
                                 /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, 
                                                 Dd, Ee, Ff, Gg, Hh, Ii, Jj, 
                                                 Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                                 Rr, Ss, Tt, Uu, Vv, Ww, Xx, 
                                                 Yy, Zz, H1, H2, MaxPorts, EP1, 
                                                 PortMap1, EP2, PortMap2, 
                                                 TableFull, EvictionReroute, 
                                                 PortScanInv, MaxTableSize, 
                                                 hosts, FreeHosts, UsedHosts, 
                                                 Ports, ExtraPorts, 
                                                 ExtraExtraPorts, FreeIPs, 
                                                 UsedIPs, Connections, 
                                                 SendQueue, RcvQueue, MAX, 
                                                 Marker1, Marker2, CmdConnect, 
                                                 CmdDisconnect, PortSpaceFull, 
                                                 stack, depth_, host_, hidx_, 
                                                 host_idx_, pidx_, port_idx_, 
                                                 depth_D, ip_, host_D, 
                                                 connDomain_, cidx_, conn_, 
                                                 host_Co, ip_C, hidx_C, 
                                                 host_idx_C, pidx_C, 
                                                 port_idx_C, host_Dis, ip_Di, 
                                                 connDomain_D, cidx_D, conn_D, 
                                                 host, ip, connDomain_Di, 
                                                 cidx_Di, conn_Di, depth_P, 
                                                 pkt_, ipkt_, entry_, conn_P, 
                                                 hostMarker_, ip_idx_, ipidx_, 
                                                 ip_P, host_P, pkt_P, ipkt_P, 
                                                 entry_P, conn_Pu, 
                                                 hostMarker_P, ip_idx_P, 
                                                 ipidx_P, ip_Pu, host_Pu, conn, 
                                                 sport, dstAddr, dport, pkt_Pr, 
                                                 hostMarker_Pr, daddr_, 
                                                 hostidx_, hidx_P, otherEntry_, 
                                                 i_, indicies_, portDomain_, 
                                                 sourcePort_, destPort_, 
                                                 new_sport_, depth_Pr, pkt_Pri, 
                                                 conn_Pr, hostMarker_Pri, 
                                                 daddr_P, hostidx_P, hidx_Pr, 
                                                 otherEntry_P, i_P, indicies_P, 
                                                 portDomain_P, sourcePort_P, 
                                                 destPort_P, new_sport_P, 
                                                 pkt_Priv, conn_Pri, 
                                                 hostMarker_Priv, daddr_Pr, 
                                                 hostidx_Pr, hidx_Pri, 
                                                 otherEntry_Pr, i_Pr, 
                                                 indicies_Pr, portDomain_Pr, 
                                                 sourcePort_Pr, destPort_Pr, 
                                                 new_sport_Pr, depth_C, host_C, 
                                                 hidx_Co, host_idx, pidx, 
                                                 port_idx, depth_Di, ip_D, 
                                                 host_Di, connDomain, cidx, 
                                                 conn_Dis, depth_Pu, pkt_Pu, 
                                                 ipkt, entry, conn_Pub, 
                                                 hostMarker_Pu, ip_idx, ipidx, 
                                                 ip_Pub, host_Pub, depth_Pri, 
                                                 pkt, conn_Priv, hostMarker, 
                                                 daddr, hostidx, hidx, 
                                                 otherEntry, i_Pri, indicies, 
                                                 portDomain, sourcePort, 
                                                 destPort, new_sport, good, 
                                                 depth_E, i_E, j_, ip_E, 
                                                 host_E, indecies_, depth, 
                                                 i_Ev, j, ip_Ev, host_Ev, 
                                                 indecies, i_C, i, aa >>

disconnectPurgeOrphans2(self) == /\ pc[self] = "disconnectPurgeOrphans2"
                                 /\ T' = SelectSeq(T, LAMBDA e: e.orig.saddr /= host_Di[self])
                                 /\ IF host_Di[self]=H1
                                       THEN /\ PortMap1' = <<>>
                                            /\ UNCHANGED PortMap2
                                       ELSE /\ PortMap2' = <<>>
                                            /\ UNCHANGED PortMap1
                                 /\ FreeHosts' = Append(FreeHosts, host_Di[self])
                                 /\ UsedHosts' = SelectSeq(UsedHosts, LAMBDA m: m /= host_Di[self])
                                 /\ PrintT(<< "Disconnect- After: ", host_Di[self], ip_D[self], Connections>>)
                                 /\ pc' = [pc EXCEPT ![self] = "disconnectRet"]
                                 /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, 
                                                 Dd, Ee, Ff, Gg, Hh, Ii, Jj, 
                                                 Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                                 Rr, Ss, Tt, Uu, Vv, Ww, Xx, 
                                                 Yy, Zz, H1, H2, MaxPorts, EP1, 
                                                 EP2, TableFull, 
                                                 EvictionReroute, PortScanInv, 
                                                 MaxTableSize, hosts, Ports, 
                                                 ExtraPorts, ExtraExtraPorts, 
                                                 FreeIPs, UsedIPs, Connections, 
                                                 SendQueue, RcvQueue, MAX, 
                                                 Marker1, Marker2, CmdConnect, 
                                                 CmdDisconnect, PortSpaceFull, 
                                                 stack, depth_, host_, hidx_, 
                                                 host_idx_, pidx_, port_idx_, 
                                                 depth_D, ip_, host_D, 
                                                 connDomain_, cidx_, conn_, 
                                                 host_Co, ip_C, hidx_C, 
                                                 host_idx_C, pidx_C, 
                                                 port_idx_C, host_Dis, ip_Di, 
                                                 connDomain_D, cidx_D, conn_D, 
                                                 host, ip, connDomain_Di, 
                                                 cidx_Di, conn_Di, depth_P, 
                                                 pkt_, ipkt_, entry_, conn_P, 
                                                 hostMarker_, ip_idx_, ipidx_, 
                                                 ip_P, host_P, pkt_P, ipkt_P, 
                                                 entry_P, conn_Pu, 
                                                 hostMarker_P, ip_idx_P, 
                                                 ipidx_P, ip_Pu, host_Pu, conn, 
                                                 sport, dstAddr, dport, pkt_Pr, 
                                                 hostMarker_Pr, daddr_, 
                                                 hostidx_, hidx_P, otherEntry_, 
                                                 i_, indicies_, portDomain_, 
                                                 sourcePort_, destPort_, 
                                                 new_sport_, depth_Pr, pkt_Pri, 
                                                 conn_Pr, hostMarker_Pri, 
                                                 daddr_P, hostidx_P, hidx_Pr, 
                                                 otherEntry_P, i_P, indicies_P, 
                                                 portDomain_P, sourcePort_P, 
                                                 destPort_P, new_sport_P, 
                                                 pkt_Priv, conn_Pri, 
                                                 hostMarker_Priv, daddr_Pr, 
                                                 hostidx_Pr, hidx_Pri, 
                                                 otherEntry_Pr, i_Pr, 
                                                 indicies_Pr, portDomain_Pr, 
                                                 sourcePort_Pr, destPort_Pr, 
                                                 new_sport_Pr, depth_C, host_C, 
                                                 hidx_Co, host_idx, pidx, 
                                                 port_idx, depth_Di, ip_D, 
                                                 host_Di, connDomain, cidx, 
                                                 conn_Dis, depth_Pu, pkt_Pu, 
                                                 ipkt, entry, conn_Pub, 
                                                 hostMarker_Pu, ip_idx, ipidx, 
                                                 ip_Pub, host_Pub, depth_Pri, 
                                                 pkt, conn_Priv, hostMarker, 
                                                 daddr, hostidx, hidx, 
                                                 otherEntry, i_Pri, indicies, 
                                                 portDomain, sourcePort, 
                                                 destPort, new_sport, good, 
                                                 depth_E, i_E, j_, ip_E, 
                                                 host_E, indecies_, depth, 
                                                 i_Ev, j, ip_Ev, host_Ev, 
                                                 indecies, i_C, i, aa >>

disconnectRet(self) == /\ pc[self] = "disconnectRet"
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ ip_D' = [ip_D EXCEPT ![self] = Head(stack[self]).ip_D]
                       /\ host_Di' = [host_Di EXCEPT ![self] = Head(stack[self]).host_Di]
                       /\ connDomain' = [connDomain EXCEPT ![self] = Head(stack[self]).connDomain]
                       /\ cidx' = [cidx EXCEPT ![self] = Head(stack[self]).cidx]
                       /\ conn_Dis' = [conn_Dis EXCEPT ![self] = Head(stack[self]).conn_Dis]
                       /\ depth_Di' = [depth_Di EXCEPT ![self] = Head(stack[self]).depth_Di]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, depth_, 
                                       host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Pu, 
                                       pkt_Pu, ipkt, entry, conn_Pub, 
                                       hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                       host_Pub, depth_Pri, pkt, conn_Priv, 
                                       hostMarker, daddr, hostidx, hidx, 
                                       otherEntry, i_Pri, indicies, portDomain, 
                                       sourcePort, destPort, new_sport, good, 
                                       depth_E, i_E, j_, ip_E, host_E, 
                                       indecies_, depth, i_Ev, j, ip_Ev, 
                                       host_Ev, indecies, i_C, i, aa >>

Disconnect(self) == disconnectStart(self) \/ disconnectIf(self)
                       \/ disconnectPurgeOrphans1(self)
                       \/ disconnectPurgeOrphans2(self)
                       \/ disconnectRet(self)

pubtoprivStart(self) == /\ pc[self] = "pubtoprivStart"
                        /\ /\ depth' = [depth EXCEPT ![self] = depth_Pu[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequence",
                                                                    pc        |->  "pubtoprivIf",
                                                                    i_Ev      |->  i_Ev[self],
                                                                    j         |->  j[self],
                                                                    ip_Ev     |->  ip_Ev[self],
                                                                    host_Ev   |->  host_Ev[self],
                                                                    indecies  |->  indecies[self],
                                                                    depth     |->  depth[self] ] >>
                                                                \o stack[self]]
                        /\ i_Ev' = [i_Ev EXCEPT ![self] = defaultInitValue]
                        /\ j' = [j EXCEPT ![self] = defaultInitValue]
                        /\ ip_Ev' = [ip_Ev EXCEPT ![self] = defaultInitValue]
                        /\ host_Ev' = [host_Ev EXCEPT ![self] = defaultInitValue]
                        /\ indecies' = [indecies EXCEPT ![self] = defaultInitValue]
                        /\ pc' = [pc EXCEPT ![self] = "evtSeqStart"]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, SendQueue, RcvQueue, MAX, 
                                        Marker1, Marker2, CmdConnect, 
                                        CmdDisconnect, PortSpaceFull, depth_, 
                                        host_, hidx_, host_idx_, pidx_, 
                                        port_idx_, depth_D, ip_, host_D, 
                                        connDomain_, cidx_, conn_, host_Co, 
                                        ip_C, hidx_C, host_idx_C, pidx_C, 
                                        port_idx_C, host_Dis, ip_Di, 
                                        connDomain_D, cidx_D, conn_D, host, ip, 
                                        connDomain_Di, cidx_Di, conn_Di, 
                                        depth_P, pkt_, ipkt_, entry_, conn_P, 
                                        hostMarker_, ip_idx_, ipidx_, ip_P, 
                                        host_P, pkt_P, ipkt_P, entry_P, 
                                        conn_Pu, hostMarker_P, ip_idx_P, 
                                        ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                        dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                        daddr_, hostidx_, hidx_P, otherEntry_, 
                                        i_, indicies_, portDomain_, 
                                        sourcePort_, destPort_, new_sport_, 
                                        depth_Pr, pkt_Pri, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth_E, 
                                        i_E, j_, ip_E, host_E, indecies_, i_C, 
                                        i, aa >>

pubtoprivIf(self) == /\ pc[self] = "pubtoprivIf"
                     /\ IF Len(SendQueue) > 0
                           THEN /\ pkt_Pu' = [pkt_Pu EXCEPT ![self] = Head(SendQueue)]
                                /\ PrintT(<<"PubToPriv", pkt_Pu'[self], Connections>>)
                                /\ SendQueue' = Tail(SendQueue)
                                /\ entry' = [entry EXCEPT ![self] = SelectSeq(T, LAMBDA e: e.reply.saddr=pkt_Pu'[self].saddr /\
                                                                                           e.reply.sport=pkt_Pu'[self].sport /\
                                                                                           e.reply.daddr=pkt_Pu'[self].daddr /\
                                                                                           e.reply.dport=pkt_Pu'[self].dport)]
                                /\ IF Len(entry'[self]) <= 0
                                      THEN /\ IF pkt_Pu'[self].dport = N
                                                 THEN /\ IF Len(FreeIPs) > 0
                                                            THEN /\ ip_idx' = [ip_idx EXCEPT ![self] = DOMAIN FreeIPs]
                                                                 /\ ipidx' = [ipidx EXCEPT ![self] = CHOOSE ipp \in ip_idx'[self] : TRUE]
                                                                 /\ ip_Pub' = [ip_Pub EXCEPT ![self] = FreeIPs[ipidx'[self]]]
                                                                 /\ FreeIPs' = SelectSeq(FreeIPs, LAMBDA d: d /= ip_Pub'[self])
                                                                 /\ UsedIPs' = Append(UsedIPs, ip_Pub'[self])
                                                                 /\ host_Pub' = [host_Pub EXCEPT ![self] = pkt_Pu'[self].saddr]
                                                                 /\ Connections' = Append(Connections, <<ip_Pub'[self], host_Pub'[self]>>)
                                                            ELSE /\ TRUE
                                                                 /\ UNCHANGED << FreeIPs, 
                                                                                 UsedIPs, 
                                                                                 Connections, 
                                                                                 ip_idx, 
                                                                                 ipidx, 
                                                                                 ip_Pub, 
                                                                                 host_Pub >>
                                                 ELSE /\ IF pkt_Pu'[self].dport = NN
                                                            THEN /\ Assert((TRUE), 
                                                                           "Failure of assertion at line 600, column 9.")
                                                            ELSE /\ Assert((TRUE), 
                                                                           "Failure of assertion at line 605, column 9.")
                                                      /\ UNCHANGED << FreeIPs, 
                                                                      UsedIPs, 
                                                                      Connections, 
                                                                      ip_idx, 
                                                                      ipidx, 
                                                                      ip_Pub, 
                                                                      host_Pub >>
                                           /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet"]
                                      ELSE /\ pc' = [pc EXCEPT ![self] = "pubtoPrivElse"]
                                           /\ UNCHANGED << FreeIPs, UsedIPs, 
                                                           Connections, ip_idx, 
                                                           ipidx, ip_Pub, 
                                                           host_Pub >>
                           ELSE /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet"]
                                /\ UNCHANGED << FreeIPs, UsedIPs, Connections, 
                                                SendQueue, pkt_Pu, entry, 
                                                ip_idx, ipidx, ip_Pub, 
                                                host_Pub >>
                     /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                     Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, 
                                     Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, 
                                     H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                     PortMap2, TableFull, EvictionReroute, 
                                     PortScanInv, MaxTableSize, hosts, 
                                     FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                     ExtraExtraPorts, T, RcvQueue, MAX, 
                                     Marker1, Marker2, CmdConnect, 
                                     CmdDisconnect, PortSpaceFull, stack, 
                                     depth_, host_, hidx_, host_idx_, pidx_, 
                                     port_idx_, depth_D, ip_, host_D, 
                                     connDomain_, cidx_, conn_, host_Co, ip_C, 
                                     hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                     host_Dis, ip_Di, connDomain_D, cidx_D, 
                                     conn_D, host, ip, connDomain_Di, cidx_Di, 
                                     conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                     conn_P, hostMarker_, ip_idx_, ipidx_, 
                                     ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                     conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                     ip_Pu, host_Pu, conn, sport, dstAddr, 
                                     dport, pkt_Pr, hostMarker_Pr, daddr_, 
                                     hostidx_, hidx_P, otherEntry_, i_, 
                                     indicies_, portDomain_, sourcePort_, 
                                     destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                     conn_Pr, hostMarker_Pri, daddr_P, 
                                     hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                     indicies_P, portDomain_P, sourcePort_P, 
                                     destPort_P, new_sport_P, pkt_Priv, 
                                     conn_Pri, hostMarker_Priv, daddr_Pr, 
                                     hostidx_Pr, hidx_Pri, otherEntry_Pr, i_Pr, 
                                     indicies_Pr, portDomain_Pr, sourcePort_Pr, 
                                     destPort_Pr, new_sport_Pr, depth_C, 
                                     host_C, hidx_Co, host_idx, pidx, port_idx, 
                                     depth_Di, ip_D, host_Di, connDomain, cidx, 
                                     conn_Dis, depth_Pu, ipkt, conn_Pub, 
                                     hostMarker_Pu, depth_Pri, pkt, conn_Priv, 
                                     hostMarker, daddr, hostidx, hidx, 
                                     otherEntry, i_Pri, indicies, portDomain, 
                                     sourcePort, destPort, new_sport, good, 
                                     depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                     depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                     i_C, i, aa >>

pubtoPrivElse(self) == /\ pc[self] = "pubtoPrivElse"
                       /\ entry' = [entry EXCEPT ![self] = Head(entry[self])]
                       /\ IF entry'[self].reply.dport=N
                             THEN /\ PrintT(<<"PubToPriv - PortShadow: ", entry'[self], pkt_Pu[self]>>)
                             ELSE /\ TRUE
                       /\ IF entry'[self].host_marker/=pkt_Pu[self].host_marker
                             THEN /\ IF pkt_Pu[self].host_marker = H1
                                        THEN /\ Marker1' = entry'[self].host_marker
                                             /\ IF entry'[self].host_marker = H2
                                                   THEN /\ EvictionReroute' = TRUE
                                                   ELSE /\ TRUE
                                                        /\ UNCHANGED EvictionReroute
                                             /\ UNCHANGED Marker2
                                        ELSE /\ Marker2' = entry'[self].host_marker
                                             /\ IF entry'[self].host_marker = H1
                                                   THEN /\ EvictionReroute' = TRUE
                                                   ELSE /\ TRUE
                                                        /\ UNCHANGED EvictionReroute
                                             /\ UNCHANGED Marker1
                                  /\ PrintT(<<"PubToPriv-Eviction Error: pkt", pkt_Pu[self], " entry", entry'[self], "Connections:", Connections, "T: ", T>>)
                             ELSE /\ TRUE
                                  /\ UNCHANGED << EvictionReroute, Marker1, 
                                                  Marker2 >>
                       /\ conn_Pub' = [conn_Pub EXCEPT ![self] = SelectSeq(Connections, LAMBDA e: entry'[self].orig.saddr = Head(e))]
                       /\ IF Len(conn_Pub'[self]) > 0
                             THEN /\ pc' = [pc EXCEPT ![self] = "pubtoprivConngt1"]
                             ELSE /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet"]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       CmdConnect, CmdDisconnect, 
                                       PortSpaceFull, stack, depth_, host_, 
                                       hidx_, host_idx_, pidx_, port_idx_, 
                                       depth_D, ip_, host_D, connDomain_, 
                                       cidx_, conn_, host_Co, ip_C, hidx_C, 
                                       host_idx_C, pidx_C, port_idx_C, 
                                       host_Dis, ip_Di, connDomain_D, cidx_D, 
                                       conn_D, host, ip, connDomain_Di, 
                                       cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                       entry_, conn_P, hostMarker_, ip_idx_, 
                                       ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                       entry_P, conn_Pu, hostMarker_P, 
                                       ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                       sport, dstAddr, dport, pkt_Pr, 
                                       hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                       otherEntry_, i_, indicies_, portDomain_, 
                                       sourcePort_, destPort_, new_sport_, 
                                       depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                       hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                       host_Pub, depth_Pri, pkt, conn_Priv, 
                                       hostMarker, daddr, hostidx, hidx, 
                                       otherEntry, i_Pri, indicies, portDomain, 
                                       sourcePort, destPort, new_sport, good, 
                                       depth_E, i_E, j_, ip_E, host_E, 
                                       indecies_, depth, i_Ev, j, ip_Ev, 
                                       host_Ev, indecies, i_C, i, aa >>

pubtoprivConngt1(self) == /\ pc[self] = "pubtoprivConngt1"
                          /\ conn_Pub' = [conn_Pub EXCEPT ![self] = Head(conn_Pub[self])]
                          /\ pc' = [pc EXCEPT ![self] = "pubtoprivConngt2"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          FreeHosts, UsedHosts, Ports, 
                                          ExtraPorts, ExtraExtraPorts, T, 
                                          FreeIPs, UsedIPs, Connections, 
                                          SendQueue, RcvQueue, MAX, Marker1, 
                                          Marker2, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, stack, depth_, host_, 
                                          hidx_, host_idx_, pidx_, port_idx_, 
                                          depth_D, ip_, host_D, connDomain_, 
                                          cidx_, conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, hostMarker_Pu, ip_idx, 
                                          ipidx, ip_Pub, host_Pub, depth_Pri, 
                                          pkt, conn_Priv, hostMarker, daddr, 
                                          hostidx, hidx, otherEntry, i_Pri, 
                                          indicies, portDomain, sourcePort, 
                                          destPort, new_sport, good, depth_E, 
                                          i_E, j_, ip_E, host_E, indecies_, 
                                          depth, i_Ev, j, ip_Ev, host_Ev, 
                                          indecies, i_C, i, aa >>

pubtoprivConngt2(self) == /\ pc[self] = "pubtoprivConngt2"
                          /\ hostMarker_Pu' = [hostMarker_Pu EXCEPT ![self] = conn_Pub[self][2]]
                          /\ IF hostMarker_Pu'[self] = H1
                                THEN /\ IF entry[self].host_marker = H2
                                           THEN /\ PortScanInv' = TRUE
                                           ELSE /\ TRUE
                                                /\ UNCHANGED PortScanInv
                                     /\ Marker1' = entry[self].host_marker
                                     /\ UNCHANGED Marker2
                                ELSE /\ IF entry[self].host_marker = H1
                                           THEN /\ PortScanInv' = TRUE
                                           ELSE /\ TRUE
                                                /\ UNCHANGED PortScanInv
                                     /\ Marker2' = entry[self].host_marker
                                     /\ UNCHANGED Marker1
                          /\ pc' = [pc EXCEPT ![self] = "pubtoprivRet"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          MaxTableSize, hosts, FreeHosts, 
                                          UsedHosts, Ports, ExtraPorts, 
                                          ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                          Connections, SendQueue, RcvQueue, 
                                          MAX, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, stack, depth_, host_, 
                                          hidx_, host_idx_, pidx_, port_idx_, 
                                          depth_D, ip_, host_D, connDomain_, 
                                          cidx_, conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, conn_Pub, ip_idx, ipidx, 
                                          ip_Pub, host_Pub, depth_Pri, pkt, 
                                          conn_Priv, hostMarker, daddr, 
                                          hostidx, hidx, otherEntry, i_Pri, 
                                          indicies, portDomain, sourcePort, 
                                          destPort, new_sport, good, depth_E, 
                                          i_E, j_, ip_E, host_E, indecies_, 
                                          depth, i_Ev, j, ip_Ev, host_Ev, 
                                          indecies, i_C, i, aa >>

pubtoprivRet(self) == /\ pc[self] = "pubtoprivRet"
                      /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                      /\ pkt_Pu' = [pkt_Pu EXCEPT ![self] = Head(stack[self]).pkt_Pu]
                      /\ ipkt' = [ipkt EXCEPT ![self] = Head(stack[self]).ipkt]
                      /\ entry' = [entry EXCEPT ![self] = Head(stack[self]).entry]
                      /\ conn_Pub' = [conn_Pub EXCEPT ![self] = Head(stack[self]).conn_Pub]
                      /\ hostMarker_Pu' = [hostMarker_Pu EXCEPT ![self] = Head(stack[self]).hostMarker_Pu]
                      /\ ip_idx' = [ip_idx EXCEPT ![self] = Head(stack[self]).ip_idx]
                      /\ ipidx' = [ipidx EXCEPT ![self] = Head(stack[self]).ipidx]
                      /\ ip_Pub' = [ip_Pub EXCEPT ![self] = Head(stack[self]).ip_Pub]
                      /\ host_Pub' = [host_Pub EXCEPT ![self] = Head(stack[self]).host_Pub]
                      /\ depth_Pu' = [depth_Pu EXCEPT ![self] = Head(stack[self]).depth_Pu]
                      /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                      /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                      Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                      Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                      Zz, H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                      PortMap2, TableFull, EvictionReroute, 
                                      PortScanInv, MaxTableSize, hosts, 
                                      FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                      ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                      Connections, SendQueue, RcvQueue, MAX, 
                                      Marker1, Marker2, CmdConnect, 
                                      CmdDisconnect, PortSpaceFull, depth_, 
                                      host_, hidx_, host_idx_, pidx_, 
                                      port_idx_, depth_D, ip_, host_D, 
                                      connDomain_, cidx_, conn_, host_Co, ip_C, 
                                      hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                      host_Dis, ip_Di, connDomain_D, cidx_D, 
                                      conn_D, host, ip, connDomain_Di, cidx_Di, 
                                      conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                      conn_P, hostMarker_, ip_idx_, ipidx_, 
                                      ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                      conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                      ip_Pu, host_Pu, conn, sport, dstAddr, 
                                      dport, pkt_Pr, hostMarker_Pr, daddr_, 
                                      hostidx_, hidx_P, otherEntry_, i_, 
                                      indicies_, portDomain_, sourcePort_, 
                                      destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                      conn_Pr, hostMarker_Pri, daddr_P, 
                                      hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                      indicies_P, portDomain_P, sourcePort_P, 
                                      destPort_P, new_sport_P, pkt_Priv, 
                                      conn_Pri, hostMarker_Priv, daddr_Pr, 
                                      hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                      i_Pr, indicies_Pr, portDomain_Pr, 
                                      sourcePort_Pr, destPort_Pr, new_sport_Pr, 
                                      depth_C, host_C, hidx_Co, host_idx, pidx, 
                                      port_idx, depth_Di, ip_D, host_Di, 
                                      connDomain, cidx, conn_Dis, depth_Pri, 
                                      pkt, conn_Priv, hostMarker, daddr, 
                                      hostidx, hidx, otherEntry, i_Pri, 
                                      indicies, portDomain, sourcePort, 
                                      destPort, new_sport, good, depth_E, i_E, 
                                      j_, ip_E, host_E, indecies_, depth, i_Ev, 
                                      j, ip_Ev, host_Ev, indecies, i_C, i, aa >>

PubToPriv(self) == pubtoprivStart(self) \/ pubtoprivIf(self)
                      \/ pubtoPrivElse(self) \/ pubtoprivConngt1(self)
                      \/ pubtoprivConngt2(self) \/ pubtoprivRet(self)

privtopubStart(self) == /\ pc[self] = "privtopubStart"
                        /\ /\ depth' = [depth EXCEPT ![self] = depth_Pri[self]]
                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequence",
                                                                    pc        |->  "privtopubIf",
                                                                    i_Ev      |->  i_Ev[self],
                                                                    j         |->  j[self],
                                                                    ip_Ev     |->  ip_Ev[self],
                                                                    host_Ev   |->  host_Ev[self],
                                                                    indecies  |->  indecies[self],
                                                                    depth     |->  depth[self] ] >>
                                                                \o stack[self]]
                        /\ i_Ev' = [i_Ev EXCEPT ![self] = defaultInitValue]
                        /\ j' = [j EXCEPT ![self] = defaultInitValue]
                        /\ ip_Ev' = [ip_Ev EXCEPT ![self] = defaultInitValue]
                        /\ host_Ev' = [host_Ev EXCEPT ![self] = defaultInitValue]
                        /\ indecies' = [indecies EXCEPT ![self] = defaultInitValue]
                        /\ pc' = [pc EXCEPT ![self] = "evtSeqStart"]
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                        EP2, PortMap2, TableFull, 
                                        EvictionReroute, PortScanInv, 
                                        MaxTableSize, hosts, FreeHosts, 
                                        UsedHosts, Ports, ExtraPorts, 
                                        ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                        Connections, SendQueue, RcvQueue, MAX, 
                                        Marker1, Marker2, CmdConnect, 
                                        CmdDisconnect, PortSpaceFull, depth_, 
                                        host_, hidx_, host_idx_, pidx_, 
                                        port_idx_, depth_D, ip_, host_D, 
                                        connDomain_, cidx_, conn_, host_Co, 
                                        ip_C, hidx_C, host_idx_C, pidx_C, 
                                        port_idx_C, host_Dis, ip_Di, 
                                        connDomain_D, cidx_D, conn_D, host, ip, 
                                        connDomain_Di, cidx_Di, conn_Di, 
                                        depth_P, pkt_, ipkt_, entry_, conn_P, 
                                        hostMarker_, ip_idx_, ipidx_, ip_P, 
                                        host_P, pkt_P, ipkt_P, entry_P, 
                                        conn_Pu, hostMarker_P, ip_idx_P, 
                                        ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                        dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                        daddr_, hostidx_, hidx_P, otherEntry_, 
                                        i_, indicies_, portDomain_, 
                                        sourcePort_, destPort_, new_sport_, 
                                        depth_Pr, pkt_Pri, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, hostMarker, daddr, 
                                        hostidx, hidx, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        destPort, new_sport, good, depth_E, 
                                        i_E, j_, ip_E, host_E, indecies_, i_C, 
                                        i, aa >>

privtopubIf(self) == /\ pc[self] = "privtopubIf"
                     /\ good' = [good EXCEPT ![self] = TRUE]
                     /\ IF Len (Connections) > 0
                           THEN /\ indicies' = [indicies EXCEPT ![self] = DOMAIN Connections]
                                /\ portDomain' = [portDomain EXCEPT ![self] = DOMAIN Ports]
                                /\ sourcePort' = [sourcePort EXCEPT ![self] = CHOOSE pr \in portDomain'[self] : TRUE]
                                /\ i_Pri' = [i_Pri EXCEPT ![self] = CHOOSE f \in indicies'[self] : TRUE]
                                /\ pc' = [pc EXCEPT ![self] = "privtopubConn"]
                           ELSE /\ pc' = [pc EXCEPT ![self] = "privtopubRet"]
                                /\ UNCHANGED << i_Pri, indicies, portDomain, 
                                                sourcePort >>
                     /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                     Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, 
                                     Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, 
                                     H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                     PortMap2, TableFull, EvictionReroute, 
                                     PortScanInv, MaxTableSize, hosts, 
                                     FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                     ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                     Connections, SendQueue, RcvQueue, MAX, 
                                     Marker1, Marker2, CmdConnect, 
                                     CmdDisconnect, PortSpaceFull, stack, 
                                     depth_, host_, hidx_, host_idx_, pidx_, 
                                     port_idx_, depth_D, ip_, host_D, 
                                     connDomain_, cidx_, conn_, host_Co, ip_C, 
                                     hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                     host_Dis, ip_Di, connDomain_D, cidx_D, 
                                     conn_D, host, ip, connDomain_Di, cidx_Di, 
                                     conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                     conn_P, hostMarker_, ip_idx_, ipidx_, 
                                     ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                     conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                     ip_Pu, host_Pu, conn, sport, dstAddr, 
                                     dport, pkt_Pr, hostMarker_Pr, daddr_, 
                                     hostidx_, hidx_P, otherEntry_, i_, 
                                     indicies_, portDomain_, sourcePort_, 
                                     destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                     conn_Pr, hostMarker_Pri, daddr_P, 
                                     hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                     indicies_P, portDomain_P, sourcePort_P, 
                                     destPort_P, new_sport_P, pkt_Priv, 
                                     conn_Pri, hostMarker_Priv, daddr_Pr, 
                                     hostidx_Pr, hidx_Pri, otherEntry_Pr, i_Pr, 
                                     indicies_Pr, portDomain_Pr, sourcePort_Pr, 
                                     destPort_Pr, new_sport_Pr, depth_C, 
                                     host_C, hidx_Co, host_idx, pidx, port_idx, 
                                     depth_Di, ip_D, host_Di, connDomain, cidx, 
                                     conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                     conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                     ip_Pub, host_Pub, depth_Pri, pkt, 
                                     conn_Priv, hostMarker, daddr, hostidx, 
                                     hidx, otherEntry, destPort, new_sport, 
                                     depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                     depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                     i_C, i, aa >>

privtopubConn(self) == /\ pc[self] = "privtopubConn"
                       /\ conn_Priv' = [conn_Priv EXCEPT ![self] = Connections[i_Pri[self]]]
                       /\ sourcePort' = [sourcePort EXCEPT ![self] = Ports[sourcePort[self]]]
                       /\ portDomain' = [portDomain EXCEPT ![self] = DOMAIN Ports]
                       /\ destPort' = [destPort EXCEPT ![self] = CHOOSE h \in portDomain'[self] : TRUE]
                       /\ pc' = [pc EXCEPT ![self] = "privtopubDport"]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, stack, 
                                       depth_, host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       hostMarker, daddr, hostidx, hidx, 
                                       otherEntry, i_Pri, indicies, new_sport, 
                                       good, depth_E, i_E, j_, ip_E, host_E, 
                                       indecies_, depth, i_Ev, j, ip_Ev, 
                                       host_Ev, indecies, i_C, i, aa >>

privtopubDport(self) == /\ pc[self] = "privtopubDport"
                        /\ destPort' = [destPort EXCEPT ![self] = Ports[destPort[self]]]
                        /\ hostidx' = [hostidx EXCEPT ![self] = DOMAIN hosts]
                        /\ hidx' = [hidx EXCEPT ![self] = CHOOSE hid \in hostidx'[self] : TRUE]
                        /\ daddr' = [daddr EXCEPT ![self] = hosts[hidx'[self]]]
                        /\ hostMarker' = [hostMarker EXCEPT ![self] = Head(Tail(conn_Priv[self]))]
                        /\ IF hostMarker'[self]=H1
                              THEN /\ IF Len(PortMap1) >= MaxPorts
                                         THEN /\ good' = [good EXCEPT ![self] = FALSE]
                                              /\ pc' = [pc EXCEPT ![self] = "privtopubMaxPorts1"]
                                              /\ UNCHANGED PortMap1
                                         ELSE /\ PortMap1' = Append(PortMap1, sourcePort[self])
                                              /\ pc' = [pc EXCEPT ![self] = "privtopubGood"]
                                              /\ good' = good
                                   /\ UNCHANGED PortMap2
                              ELSE /\ IF Len(PortMap2) >= MaxPorts
                                         THEN /\ good' = [good EXCEPT ![self] = FALSE]
                                              /\ pc' = [pc EXCEPT ![self] = "privtopubMaxPorts2"]
                                              /\ UNCHANGED PortMap2
                                         ELSE /\ PortMap2' = Append(PortMap2, sourcePort[self])
                                              /\ pc' = [pc EXCEPT ![self] = "privtopubGood"]
                                              /\ good' = good
                                   /\ UNCHANGED PortMap1
                        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                        Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                        Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                        Zz, H1, H2, MaxPorts, EP1, EP2, 
                                        TableFull, EvictionReroute, 
                                        PortScanInv, MaxTableSize, hosts, 
                                        FreeHosts, UsedHosts, Ports, 
                                        ExtraPorts, ExtraExtraPorts, T, 
                                        FreeIPs, UsedIPs, Connections, 
                                        SendQueue, RcvQueue, MAX, Marker1, 
                                        Marker2, CmdConnect, CmdDisconnect, 
                                        PortSpaceFull, stack, depth_, host_, 
                                        hidx_, host_idx_, pidx_, port_idx_, 
                                        depth_D, ip_, host_D, connDomain_, 
                                        cidx_, conn_, host_Co, ip_C, hidx_C, 
                                        host_idx_C, pidx_C, port_idx_C, 
                                        host_Dis, ip_Di, connDomain_D, cidx_D, 
                                        conn_D, host, ip, connDomain_Di, 
                                        cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                        entry_, conn_P, hostMarker_, ip_idx_, 
                                        ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                        entry_P, conn_Pu, hostMarker_P, 
                                        ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                        conn, sport, dstAddr, dport, pkt_Pr, 
                                        hostMarker_Pr, daddr_, hostidx_, 
                                        hidx_P, otherEntry_, i_, indicies_, 
                                        portDomain_, sourcePort_, destPort_, 
                                        new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                        hostMarker_Pri, daddr_P, hostidx_P, 
                                        hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                        portDomain_P, sourcePort_P, destPort_P, 
                                        new_sport_P, pkt_Priv, conn_Pri, 
                                        hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                        hidx_Pri, otherEntry_Pr, i_Pr, 
                                        indicies_Pr, portDomain_Pr, 
                                        sourcePort_Pr, destPort_Pr, 
                                        new_sport_Pr, depth_C, host_C, hidx_Co, 
                                        host_idx, pidx, port_idx, depth_Di, 
                                        ip_D, host_Di, connDomain, cidx, 
                                        conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                        entry, conn_Pub, hostMarker_Pu, ip_idx, 
                                        ipidx, ip_Pub, host_Pub, depth_Pri, 
                                        pkt, conn_Priv, otherEntry, i_Pri, 
                                        indicies, portDomain, sourcePort, 
                                        new_sport, depth_E, i_E, j_, ip_E, 
                                        host_E, indecies_, depth, i_Ev, j, 
                                        ip_Ev, host_Ev, indecies, i_C, i, aa >>

privtopubMaxPorts1(self) == /\ pc[self] = "privtopubMaxPorts1"
                            /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                            /\ pkt' = [pkt EXCEPT ![self] = Head(stack[self]).pkt]
                            /\ conn_Priv' = [conn_Priv EXCEPT ![self] = Head(stack[self]).conn_Priv]
                            /\ hostMarker' = [hostMarker EXCEPT ![self] = Head(stack[self]).hostMarker]
                            /\ daddr' = [daddr EXCEPT ![self] = Head(stack[self]).daddr]
                            /\ hostidx' = [hostidx EXCEPT ![self] = Head(stack[self]).hostidx]
                            /\ hidx' = [hidx EXCEPT ![self] = Head(stack[self]).hidx]
                            /\ otherEntry' = [otherEntry EXCEPT ![self] = Head(stack[self]).otherEntry]
                            /\ i_Pri' = [i_Pri EXCEPT ![self] = Head(stack[self]).i_Pri]
                            /\ indicies' = [indicies EXCEPT ![self] = Head(stack[self]).indicies]
                            /\ portDomain' = [portDomain EXCEPT ![self] = Head(stack[self]).portDomain]
                            /\ sourcePort' = [sourcePort EXCEPT ![self] = Head(stack[self]).sourcePort]
                            /\ destPort' = [destPort EXCEPT ![self] = Head(stack[self]).destPort]
                            /\ new_sport' = [new_sport EXCEPT ![self] = Head(stack[self]).new_sport]
                            /\ good' = [good EXCEPT ![self] = Head(stack[self]).good]
                            /\ depth_Pri' = [depth_Pri EXCEPT ![self] = Head(stack[self]).depth_Pri]
                            /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                            /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                            Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                            Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                            Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                            EP1, PortMap1, EP2, PortMap2, 
                                            TableFull, EvictionReroute, 
                                            PortScanInv, MaxTableSize, hosts, 
                                            FreeHosts, UsedHosts, Ports, 
                                            ExtraPorts, ExtraExtraPorts, T, 
                                            FreeIPs, UsedIPs, Connections, 
                                            SendQueue, RcvQueue, MAX, Marker1, 
                                            Marker2, CmdConnect, CmdDisconnect, 
                                            PortSpaceFull, depth_, host_, 
                                            hidx_, host_idx_, pidx_, port_idx_, 
                                            depth_D, ip_, host_D, connDomain_, 
                                            cidx_, conn_, host_Co, ip_C, 
                                            hidx_C, host_idx_C, pidx_C, 
                                            port_idx_C, host_Dis, ip_Di, 
                                            connDomain_D, cidx_D, conn_D, host, 
                                            ip, connDomain_Di, cidx_Di, 
                                            conn_Di, depth_P, pkt_, ipkt_, 
                                            entry_, conn_P, hostMarker_, 
                                            ip_idx_, ipidx_, ip_P, host_P, 
                                            pkt_P, ipkt_P, entry_P, conn_Pu, 
                                            hostMarker_P, ip_idx_P, ipidx_P, 
                                            ip_Pu, host_Pu, conn, sport, 
                                            dstAddr, dport, pkt_Pr, 
                                            hostMarker_Pr, daddr_, hostidx_, 
                                            hidx_P, otherEntry_, i_, indicies_, 
                                            portDomain_, sourcePort_, 
                                            destPort_, new_sport_, depth_Pr, 
                                            pkt_Pri, conn_Pr, hostMarker_Pri, 
                                            daddr_P, hostidx_P, hidx_Pr, 
                                            otherEntry_P, i_P, indicies_P, 
                                            portDomain_P, sourcePort_P, 
                                            destPort_P, new_sport_P, pkt_Priv, 
                                            conn_Pri, hostMarker_Priv, 
                                            daddr_Pr, hostidx_Pr, hidx_Pri, 
                                            otherEntry_Pr, i_Pr, indicies_Pr, 
                                            portDomain_Pr, sourcePort_Pr, 
                                            destPort_Pr, new_sport_Pr, depth_C, 
                                            host_C, hidx_Co, host_idx, pidx, 
                                            port_idx, depth_Di, ip_D, host_Di, 
                                            connDomain, cidx, conn_Dis, 
                                            depth_Pu, pkt_Pu, ipkt, entry, 
                                            conn_Pub, hostMarker_Pu, ip_idx, 
                                            ipidx, ip_Pub, host_Pub, depth_E, 
                                            i_E, j_, ip_E, host_E, indecies_, 
                                            depth, i_Ev, j, ip_Ev, host_Ev, 
                                            indecies, i_C, i, aa >>

privtopubMaxPorts2(self) == /\ pc[self] = "privtopubMaxPorts2"
                            /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                            /\ pkt' = [pkt EXCEPT ![self] = Head(stack[self]).pkt]
                            /\ conn_Priv' = [conn_Priv EXCEPT ![self] = Head(stack[self]).conn_Priv]
                            /\ hostMarker' = [hostMarker EXCEPT ![self] = Head(stack[self]).hostMarker]
                            /\ daddr' = [daddr EXCEPT ![self] = Head(stack[self]).daddr]
                            /\ hostidx' = [hostidx EXCEPT ![self] = Head(stack[self]).hostidx]
                            /\ hidx' = [hidx EXCEPT ![self] = Head(stack[self]).hidx]
                            /\ otherEntry' = [otherEntry EXCEPT ![self] = Head(stack[self]).otherEntry]
                            /\ i_Pri' = [i_Pri EXCEPT ![self] = Head(stack[self]).i_Pri]
                            /\ indicies' = [indicies EXCEPT ![self] = Head(stack[self]).indicies]
                            /\ portDomain' = [portDomain EXCEPT ![self] = Head(stack[self]).portDomain]
                            /\ sourcePort' = [sourcePort EXCEPT ![self] = Head(stack[self]).sourcePort]
                            /\ destPort' = [destPort EXCEPT ![self] = Head(stack[self]).destPort]
                            /\ new_sport' = [new_sport EXCEPT ![self] = Head(stack[self]).new_sport]
                            /\ good' = [good EXCEPT ![self] = Head(stack[self]).good]
                            /\ depth_Pri' = [depth_Pri EXCEPT ![self] = Head(stack[self]).depth_Pri]
                            /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                            /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                            Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                            Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                            Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                            EP1, PortMap1, EP2, PortMap2, 
                                            TableFull, EvictionReroute, 
                                            PortScanInv, MaxTableSize, hosts, 
                                            FreeHosts, UsedHosts, Ports, 
                                            ExtraPorts, ExtraExtraPorts, T, 
                                            FreeIPs, UsedIPs, Connections, 
                                            SendQueue, RcvQueue, MAX, Marker1, 
                                            Marker2, CmdConnect, CmdDisconnect, 
                                            PortSpaceFull, depth_, host_, 
                                            hidx_, host_idx_, pidx_, port_idx_, 
                                            depth_D, ip_, host_D, connDomain_, 
                                            cidx_, conn_, host_Co, ip_C, 
                                            hidx_C, host_idx_C, pidx_C, 
                                            port_idx_C, host_Dis, ip_Di, 
                                            connDomain_D, cidx_D, conn_D, host, 
                                            ip, connDomain_Di, cidx_Di, 
                                            conn_Di, depth_P, pkt_, ipkt_, 
                                            entry_, conn_P, hostMarker_, 
                                            ip_idx_, ipidx_, ip_P, host_P, 
                                            pkt_P, ipkt_P, entry_P, conn_Pu, 
                                            hostMarker_P, ip_idx_P, ipidx_P, 
                                            ip_Pu, host_Pu, conn, sport, 
                                            dstAddr, dport, pkt_Pr, 
                                            hostMarker_Pr, daddr_, hostidx_, 
                                            hidx_P, otherEntry_, i_, indicies_, 
                                            portDomain_, sourcePort_, 
                                            destPort_, new_sport_, depth_Pr, 
                                            pkt_Pri, conn_Pr, hostMarker_Pri, 
                                            daddr_P, hostidx_P, hidx_Pr, 
                                            otherEntry_P, i_P, indicies_P, 
                                            portDomain_P, sourcePort_P, 
                                            destPort_P, new_sport_P, pkt_Priv, 
                                            conn_Pri, hostMarker_Priv, 
                                            daddr_Pr, hostidx_Pr, hidx_Pri, 
                                            otherEntry_Pr, i_Pr, indicies_Pr, 
                                            portDomain_Pr, sourcePort_Pr, 
                                            destPort_Pr, new_sport_Pr, depth_C, 
                                            host_C, hidx_Co, host_idx, pidx, 
                                            port_idx, depth_Di, ip_D, host_Di, 
                                            connDomain, cidx, conn_Dis, 
                                            depth_Pu, pkt_Pu, ipkt, entry, 
                                            conn_Pub, hostMarker_Pu, ip_idx, 
                                            ipidx, ip_Pub, host_Pub, depth_E, 
                                            i_E, j_, ip_E, host_E, indecies_, 
                                            depth, i_Ev, j, ip_Ev, host_Ev, 
                                            indecies, i_C, i, aa >>

privtopubGood(self) == /\ pc[self] = "privtopubGood"
                       /\ IF good[self]
                             THEN /\ pc' = [pc EXCEPT ![self] = "privToPubPkt1"]
                             ELSE /\ pc' = [pc EXCEPT ![self] = "privtopubRet"]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, stack, 
                                       depth_, host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i_C, i, aa >>

privToPubPkt1(self) == /\ pc[self] = "privToPubPkt1"
                       /\ IF sourcePort[self] = N
                             THEN /\ IF hostMarker[self]=H1
                                        THEN /\ sourcePort' = [sourcePort EXCEPT ![self] = EP1]
                                        ELSE /\ sourcePort' = [sourcePort EXCEPT ![self] = EP2]
                             ELSE /\ TRUE
                                  /\ UNCHANGED sourcePort
                       /\ pkt' = [pkt EXCEPT ![self] = [saddr |-> Head(conn_Priv[self]), sport |-> sourcePort'[self],
                                                        daddr |-> daddr[self], dport |-> destPort[self],
                                                        host_marker |-> hostMarker[self]
                                                       ]]
                       /\ PrintT(<<"PrivToPub - pkt: ", conn_Priv[self], pkt'[self]>>)
                       /\ entry' = [entry EXCEPT ![self] = [host_marker |-> hostMarker[self],
                                                            orig |-> [saddr |-> pkt'[self].saddr, sport |-> pkt'[self].sport,
                                                                      daddr |-> pkt'[self].daddr, dport |-> pkt'[self].dport],
                                                            reply |-> [saddr |-> pkt'[self].daddr, sport |-> pkt'[self].dport,
                                                                       daddr |-> N,  dport |-> pkt'[self].sport ]]]
                       /\ otherEntry' = [otherEntry EXCEPT ![self] = SelectSeq(T, LAMBDA k: k.reply.saddr=pkt'[self].daddr /\ k.reply.sport=pkt'[self].dport /\
                                                                                            k.reply.daddr=N /\ k.reply.dport=pkt'[self].sport /\
                                                                                            k.hostMarker /= hostMarker[self])]
                       /\ IF Len(otherEntry'[self]) > 0
                             THEN /\ PrintT("Evict")
                                  /\ IF Len(ExtraPorts) > 0
                                        THEN /\ new_sport' = [new_sport EXCEPT ![self] = Head(ExtraPorts)]
                                             /\ ExtraPorts' = Tail(ExtraPorts)
                                             /\ pc' = [pc EXCEPT ![self] = "privToPubNewPort"]
                                             /\ UNCHANGED PortSpaceFull
                                        ELSE /\ PortSpaceFull' = TRUE
                                             /\ pc' = [pc EXCEPT ![self] = "privToPubAppendT"]
                                             /\ UNCHANGED << ExtraPorts, 
                                                             new_sport >>
                             ELSE /\ pc' = [pc EXCEPT ![self] = "privToPubAppendT"]
                                  /\ UNCHANGED << ExtraPorts, PortSpaceFull, 
                                                  new_sport >>
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraExtraPorts, T, 
                                       FreeIPs, UsedIPs, Connections, 
                                       SendQueue, RcvQueue, MAX, Marker1, 
                                       Marker2, CmdConnect, CmdDisconnect, 
                                       stack, depth_, host_, hidx_, host_idx_, 
                                       pidx_, port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, conn_Priv, 
                                       hostMarker, daddr, hostidx, hidx, i_Pri, 
                                       indicies, portDomain, destPort, good, 
                                       depth_E, i_E, j_, ip_E, host_E, 
                                       indecies_, depth, i_Ev, j, ip_Ev, 
                                       host_Ev, indecies, i_C, i, aa >>

privToPubNewPort(self) == /\ pc[self] = "privToPubNewPort"
                          /\ entry' = [entry EXCEPT ![self] =                  [host_marker |-> hostMarker[self],
                                                              orig |-> [saddr |-> pkt[self].saddr, sport |-> pkt[self].sport,
                                                                        daddr |-> pkt[self].daddr, dport |-> pkt[self].dport],
                                                              reply |-> [saddr |-> pkt[self].daddr, sport |-> pkt[self].dport,
                                                                         daddr |-> N,  dport |-> new_sport[self] ]]]
                          /\ pkt' = [pkt EXCEPT ![self].sport = new_sport[self]]
                          /\ pc' = [pc EXCEPT ![self] = "privToPubAppendT"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          TableFull, EvictionReroute, 
                                          PortScanInv, MaxTableSize, hosts, 
                                          FreeHosts, UsedHosts, Ports, 
                                          ExtraPorts, ExtraExtraPorts, T, 
                                          FreeIPs, UsedIPs, Connections, 
                                          SendQueue, RcvQueue, MAX, Marker1, 
                                          Marker2, CmdConnect, CmdDisconnect, 
                                          PortSpaceFull, stack, depth_, host_, 
                                          hidx_, host_idx_, pidx_, port_idx_, 
                                          depth_D, ip_, host_D, connDomain_, 
                                          cidx_, conn_, host_Co, ip_C, hidx_C, 
                                          host_idx_C, pidx_C, port_idx_C, 
                                          host_Dis, ip_Di, connDomain_D, 
                                          cidx_D, conn_D, host, ip, 
                                          connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, conn_Pub, hostMarker_Pu, 
                                          ip_idx, ipidx, ip_Pub, host_Pub, 
                                          depth_Pri, conn_Priv, hostMarker, 
                                          daddr, hostidx, hidx, otherEntry, 
                                          i_Pri, indicies, portDomain, 
                                          sourcePort, destPort, new_sport, 
                                          good, depth_E, i_E, j_, ip_E, host_E, 
                                          indecies_, depth, i_Ev, j, ip_Ev, 
                                          host_Ev, indecies, i_C, i, aa >>

privToPubAppendT(self) == /\ pc[self] = "privToPubAppendT"
                          /\ T' = Append(T, entry[self])
                          /\ IF Len(T') >= MaxTableSize
                                THEN /\ TableFull' = TRUE
                                ELSE /\ TRUE
                                     /\ UNCHANGED TableFull
                          /\ pc' = [pc EXCEPT ![self] = "privtopubPkt"]
                          /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                          Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                          Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                          Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                          EP1, PortMap1, EP2, PortMap2, 
                                          EvictionReroute, PortScanInv, 
                                          MaxTableSize, hosts, FreeHosts, 
                                          UsedHosts, Ports, ExtraPorts, 
                                          ExtraExtraPorts, FreeIPs, UsedIPs, 
                                          Connections, SendQueue, RcvQueue, 
                                          MAX, Marker1, Marker2, CmdConnect, 
                                          CmdDisconnect, PortSpaceFull, stack, 
                                          depth_, host_, hidx_, host_idx_, 
                                          pidx_, port_idx_, depth_D, ip_, 
                                          host_D, connDomain_, cidx_, conn_, 
                                          host_Co, ip_C, hidx_C, host_idx_C, 
                                          pidx_C, port_idx_C, host_Dis, ip_Di, 
                                          connDomain_D, cidx_D, conn_D, host, 
                                          ip, connDomain_Di, cidx_Di, conn_Di, 
                                          depth_P, pkt_, ipkt_, entry_, conn_P, 
                                          hostMarker_, ip_idx_, ipidx_, ip_P, 
                                          host_P, pkt_P, ipkt_P, entry_P, 
                                          conn_Pu, hostMarker_P, ip_idx_P, 
                                          ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                          dstAddr, dport, pkt_Pr, 
                                          hostMarker_Pr, daddr_, hostidx_, 
                                          hidx_P, otherEntry_, i_, indicies_, 
                                          portDomain_, sourcePort_, destPort_, 
                                          new_sport_, depth_Pr, pkt_Pri, 
                                          conn_Pr, hostMarker_Pri, daddr_P, 
                                          hostidx_P, hidx_Pr, otherEntry_P, 
                                          i_P, indicies_P, portDomain_P, 
                                          sourcePort_P, destPort_P, 
                                          new_sport_P, pkt_Priv, conn_Pri, 
                                          hostMarker_Priv, daddr_Pr, 
                                          hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                          i_Pr, indicies_Pr, portDomain_Pr, 
                                          sourcePort_Pr, destPort_Pr, 
                                          new_sport_Pr, depth_C, host_C, 
                                          hidx_Co, host_idx, pidx, port_idx, 
                                          depth_Di, ip_D, host_Di, connDomain, 
                                          cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                          ipkt, entry, conn_Pub, hostMarker_Pu, 
                                          ip_idx, ipidx, ip_Pub, host_Pub, 
                                          depth_Pri, pkt, conn_Priv, 
                                          hostMarker, daddr, hostidx, hidx, 
                                          otherEntry, i_Pri, indicies, 
                                          portDomain, sourcePort, destPort, 
                                          new_sport, good, depth_E, i_E, j_, 
                                          ip_E, host_E, indecies_, depth, i_Ev, 
                                          j, ip_Ev, host_Ev, indecies, i_C, i, 
                                          aa >>

privtopubPkt(self) == /\ pc[self] = "privtopubPkt"
                      /\ pkt' = [pkt EXCEPT ![self] = [saddr |->pkt[self].daddr, sport |-> pkt[self].dport,
                                                       daddr |-> N, dport |-> pkt[self].sport,
                                                       host_marker |-> hostMarker[self]]]
                      /\ SendQueue' = Append(SendQueue, pkt'[self])
                      /\ pc' = [pc EXCEPT ![self] = "privtopubRet"]
                      /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                      Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                      Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                      Zz, H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                      PortMap2, TableFull, EvictionReroute, 
                                      PortScanInv, MaxTableSize, hosts, 
                                      FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                      ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                      Connections, RcvQueue, MAX, Marker1, 
                                      Marker2, CmdConnect, CmdDisconnect, 
                                      PortSpaceFull, stack, depth_, host_, 
                                      hidx_, host_idx_, pidx_, port_idx_, 
                                      depth_D, ip_, host_D, connDomain_, cidx_, 
                                      conn_, host_Co, ip_C, hidx_C, host_idx_C, 
                                      pidx_C, port_idx_C, host_Dis, ip_Di, 
                                      connDomain_D, cidx_D, conn_D, host, ip, 
                                      connDomain_Di, cidx_Di, conn_Di, depth_P, 
                                      pkt_, ipkt_, entry_, conn_P, hostMarker_, 
                                      ip_idx_, ipidx_, ip_P, host_P, pkt_P, 
                                      ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                      ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                      sport, dstAddr, dport, pkt_Pr, 
                                      hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                      otherEntry_, i_, indicies_, portDomain_, 
                                      sourcePort_, destPort_, new_sport_, 
                                      depth_Pr, pkt_Pri, conn_Pr, 
                                      hostMarker_Pri, daddr_P, hostidx_P, 
                                      hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                      portDomain_P, sourcePort_P, destPort_P, 
                                      new_sport_P, pkt_Priv, conn_Pri, 
                                      hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                      hidx_Pri, otherEntry_Pr, i_Pr, 
                                      indicies_Pr, portDomain_Pr, 
                                      sourcePort_Pr, destPort_Pr, new_sport_Pr, 
                                      depth_C, host_C, hidx_Co, host_idx, pidx, 
                                      port_idx, depth_Di, ip_D, host_Di, 
                                      connDomain, cidx, conn_Dis, depth_Pu, 
                                      pkt_Pu, ipkt, entry, conn_Pub, 
                                      hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                      host_Pub, depth_Pri, conn_Priv, 
                                      hostMarker, daddr, hostidx, hidx, 
                                      otherEntry, i_Pri, indicies, portDomain, 
                                      sourcePort, destPort, new_sport, good, 
                                      depth_E, i_E, j_, ip_E, host_E, 
                                      indecies_, depth, i_Ev, j, ip_Ev, 
                                      host_Ev, indecies, i_C, i, aa >>

privtopubRet(self) == /\ pc[self] = "privtopubRet"
                      /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                      /\ pkt' = [pkt EXCEPT ![self] = Head(stack[self]).pkt]
                      /\ conn_Priv' = [conn_Priv EXCEPT ![self] = Head(stack[self]).conn_Priv]
                      /\ hostMarker' = [hostMarker EXCEPT ![self] = Head(stack[self]).hostMarker]
                      /\ daddr' = [daddr EXCEPT ![self] = Head(stack[self]).daddr]
                      /\ hostidx' = [hostidx EXCEPT ![self] = Head(stack[self]).hostidx]
                      /\ hidx' = [hidx EXCEPT ![self] = Head(stack[self]).hidx]
                      /\ otherEntry' = [otherEntry EXCEPT ![self] = Head(stack[self]).otherEntry]
                      /\ i_Pri' = [i_Pri EXCEPT ![self] = Head(stack[self]).i_Pri]
                      /\ indicies' = [indicies EXCEPT ![self] = Head(stack[self]).indicies]
                      /\ portDomain' = [portDomain EXCEPT ![self] = Head(stack[self]).portDomain]
                      /\ sourcePort' = [sourcePort EXCEPT ![self] = Head(stack[self]).sourcePort]
                      /\ destPort' = [destPort EXCEPT ![self] = Head(stack[self]).destPort]
                      /\ new_sport' = [new_sport EXCEPT ![self] = Head(stack[self]).new_sport]
                      /\ good' = [good EXCEPT ![self] = Head(stack[self]).good]
                      /\ depth_Pri' = [depth_Pri EXCEPT ![self] = Head(stack[self]).depth_Pri]
                      /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                      /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                      Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                      Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                      Zz, H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                      PortMap2, TableFull, EvictionReroute, 
                                      PortScanInv, MaxTableSize, hosts, 
                                      FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                      ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                      Connections, SendQueue, RcvQueue, MAX, 
                                      Marker1, Marker2, CmdConnect, 
                                      CmdDisconnect, PortSpaceFull, depth_, 
                                      host_, hidx_, host_idx_, pidx_, 
                                      port_idx_, depth_D, ip_, host_D, 
                                      connDomain_, cidx_, conn_, host_Co, ip_C, 
                                      hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                      host_Dis, ip_Di, connDomain_D, cidx_D, 
                                      conn_D, host, ip, connDomain_Di, cidx_Di, 
                                      conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                      conn_P, hostMarker_, ip_idx_, ipidx_, 
                                      ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                      conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                      ip_Pu, host_Pu, conn, sport, dstAddr, 
                                      dport, pkt_Pr, hostMarker_Pr, daddr_, 
                                      hostidx_, hidx_P, otherEntry_, i_, 
                                      indicies_, portDomain_, sourcePort_, 
                                      destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                      conn_Pr, hostMarker_Pri, daddr_P, 
                                      hostidx_P, hidx_Pr, otherEntry_P, i_P, 
                                      indicies_P, portDomain_P, sourcePort_P, 
                                      destPort_P, new_sport_P, pkt_Priv, 
                                      conn_Pri, hostMarker_Priv, daddr_Pr, 
                                      hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                      i_Pr, indicies_Pr, portDomain_Pr, 
                                      sourcePort_Pr, destPort_Pr, new_sport_Pr, 
                                      depth_C, host_C, hidx_Co, host_idx, pidx, 
                                      port_idx, depth_Di, ip_D, host_Di, 
                                      connDomain, cidx, conn_Dis, depth_Pu, 
                                      pkt_Pu, ipkt, entry, conn_Pub, 
                                      hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                      host_Pub, depth_E, i_E, j_, ip_E, host_E, 
                                      indecies_, depth, i_Ev, j, ip_Ev, 
                                      host_Ev, indecies, i_C, i, aa >>

PrivToPub(self) == privtopubStart(self) \/ privtopubIf(self)
                      \/ privtopubConn(self) \/ privtopubDport(self)
                      \/ privtopubMaxPorts1(self)
                      \/ privtopubMaxPorts2(self) \/ privtopubGood(self)
                      \/ privToPubPkt1(self) \/ privToPubNewPort(self)
                      \/ privToPubAppendT(self) \/ privtopubPkt(self)
                      \/ privtopubRet(self)

portscan1_(self) == /\ pc[self] = "portscan1_"
                    /\ /\ host_Co' = [host_Co EXCEPT ![self] = 1]
                       /\ ip_C' = [ip_C EXCEPT ![self] = B]
                       /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ConnectMan",
                                                                pc        |->  "portscan11",
                                                                hidx_C    |->  hidx_C[self],
                                                                host_idx_C |->  host_idx_C[self],
                                                                pidx_C    |->  pidx_C[self],
                                                                port_idx_C |->  port_idx_C[self],
                                                                host_Co   |->  host_Co[self],
                                                                ip_C      |->  ip_C[self] ] >>
                                                            \o stack[self]]
                    /\ hidx_C' = [hidx_C EXCEPT ![self] = defaultInitValue]
                    /\ host_idx_C' = [host_idx_C EXCEPT ![self] = defaultInitValue]
                    /\ pidx_C' = [pidx_C EXCEPT ![self] = defaultInitValue]
                    /\ port_idx_C' = [port_idx_C EXCEPT ![self] = defaultInitValue]
                    /\ pc' = [pc EXCEPT ![self] = "connectManStart"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Dis, ip_Di, 
                                    connDomain_D, cidx_D, conn_D, host, ip, 
                                    connDomain_Di, cidx_Di, conn_Di, depth_P, 
                                    pkt_, ipkt_, entry_, conn_P, hostMarker_, 
                                    ip_idx_, ipidx_, ip_P, host_P, pkt_P, 
                                    ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                    ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                    sport, dstAddr, dport, pkt_Pr, 
                                    hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                    otherEntry_, i_, indicies_, portDomain_, 
                                    sourcePort_, destPort_, new_sport_, 
                                    depth_Pr, pkt_Pri, conn_Pr, hostMarker_Pri, 
                                    daddr_P, hostidx_P, hidx_Pr, otherEntry_P, 
                                    i_P, indicies_P, portDomain_P, 
                                    sourcePort_P, destPort_P, new_sport_P, 
                                    pkt_Priv, conn_Pri, hostMarker_Priv, 
                                    daddr_Pr, hostidx_Pr, hidx_Pri, 
                                    otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan11(self) == /\ pc[self] = "portscan11"
                    /\ PrintT(<<"SendQueue:", SendQueue, T>>)
                    /\ pc' = [pc EXCEPT ![self] = "portscan2_"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    stack, depth_, host_, hidx_, host_idx_, 
                                    pidx_, port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan2_(self) == /\ pc[self] = "portscan2_"
                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PrivToPubMan",
                                                             pc        |->  "portscan21",
                                                             pkt_Priv  |->  pkt_Priv[self],
                                                             conn_Pri  |->  conn_Pri[self],
                                                             hostMarker_Priv |->  hostMarker_Priv[self],
                                                             daddr_Pr  |->  daddr_Pr[self],
                                                             hostidx_Pr |->  hostidx_Pr[self],
                                                             hidx_Pri  |->  hidx_Pri[self],
                                                             otherEntry_Pr |->  otherEntry_Pr[self],
                                                             i_Pr      |->  i_Pr[self],
                                                             indicies_Pr |->  indicies_Pr[self],
                                                             portDomain_Pr |->  portDomain_Pr[self],
                                                             sourcePort_Pr |->  sourcePort_Pr[self],
                                                             destPort_Pr |->  destPort_Pr[self],
                                                             new_sport_Pr |->  new_sport_Pr[self] ] >>
                                                         \o stack[self]]
                    /\ pkt_Priv' = [pkt_Priv EXCEPT ![self] = defaultInitValue]
                    /\ conn_Pri' = [conn_Pri EXCEPT ![self] = defaultInitValue]
                    /\ hostMarker_Priv' = [hostMarker_Priv EXCEPT ![self] = defaultInitValue]
                    /\ daddr_Pr' = [daddr_Pr EXCEPT ![self] = defaultInitValue]
                    /\ hostidx_Pr' = [hostidx_Pr EXCEPT ![self] = defaultInitValue]
                    /\ hidx_Pri' = [hidx_Pri EXCEPT ![self] = defaultInitValue]
                    /\ otherEntry_Pr' = [otherEntry_Pr EXCEPT ![self] = defaultInitValue]
                    /\ i_Pr' = [i_Pr EXCEPT ![self] = defaultInitValue]
                    /\ indicies_Pr' = [indicies_Pr EXCEPT ![self] = defaultInitValue]
                    /\ portDomain_Pr' = [portDomain_Pr EXCEPT ![self] = defaultInitValue]
                    /\ sourcePort_Pr' = [sourcePort_Pr EXCEPT ![self] = defaultInitValue]
                    /\ destPort_Pr' = [destPort_Pr EXCEPT ![self] = defaultInitValue]
                    /\ new_sport_Pr' = [new_sport_Pr EXCEPT ![self] = defaultInitValue]
                    /\ pc' = [pc EXCEPT ![self] = "privtopubManStart"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan21(self) == /\ pc[self] = "portscan21"
                    /\ PrintT(<<"SendQueue:", SendQueue, T>>)
                    /\ pc' = [pc EXCEPT ![self] = "portscan3_"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    stack, depth_, host_, hidx_, host_idx_, 
                                    pidx_, port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan3_(self) == /\ pc[self] = "portscan3_"
                    /\ /\ host' = [host EXCEPT ![self] = 1]
                       /\ ip' = [ip EXCEPT ![self] = B]
                       /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "DisconnectVulnMan",
                                                                pc        |->  "portscan31",
                                                                connDomain_Di |->  connDomain_Di[self],
                                                                cidx_Di   |->  cidx_Di[self],
                                                                conn_Di   |->  conn_Di[self],
                                                                host      |->  host[self],
                                                                ip        |->  ip[self] ] >>
                                                            \o stack[self]]
                    /\ connDomain_Di' = [connDomain_Di EXCEPT ![self] = defaultInitValue]
                    /\ cidx_Di' = [cidx_Di EXCEPT ![self] = defaultInitValue]
                    /\ conn_Di' = [conn_Di EXCEPT ![self] = defaultInitValue]
                    /\ pc' = [pc EXCEPT ![self] = "disconnectVulnManStart"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan31(self) == /\ pc[self] = "portscan31"
                    /\ PrintT(<<"SendQueue:", SendQueue, T>>)
                    /\ pc' = [pc EXCEPT ![self] = "portscan4_"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    stack, depth_, host_, hidx_, host_idx_, 
                                    pidx_, port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan4_(self) == /\ pc[self] = "portscan4_"
                    /\ /\ host_Co' = [host_Co EXCEPT ![self] = 2]
                       /\ ip_C' = [ip_C EXCEPT ![self] = B]
                       /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ConnectMan",
                                                                pc        |->  "portscan41",
                                                                hidx_C    |->  hidx_C[self],
                                                                host_idx_C |->  host_idx_C[self],
                                                                pidx_C    |->  pidx_C[self],
                                                                port_idx_C |->  port_idx_C[self],
                                                                host_Co   |->  host_Co[self],
                                                                ip_C      |->  ip_C[self] ] >>
                                                            \o stack[self]]
                    /\ hidx_C' = [hidx_C EXCEPT ![self] = defaultInitValue]
                    /\ host_idx_C' = [host_idx_C EXCEPT ![self] = defaultInitValue]
                    /\ pidx_C' = [pidx_C EXCEPT ![self] = defaultInitValue]
                    /\ port_idx_C' = [port_idx_C EXCEPT ![self] = defaultInitValue]
                    /\ pc' = [pc EXCEPT ![self] = "connectManStart"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Dis, ip_Di, 
                                    connDomain_D, cidx_D, conn_D, host, ip, 
                                    connDomain_Di, cidx_Di, conn_Di, depth_P, 
                                    pkt_, ipkt_, entry_, conn_P, hostMarker_, 
                                    ip_idx_, ipidx_, ip_P, host_P, pkt_P, 
                                    ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                    ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                    sport, dstAddr, dport, pkt_Pr, 
                                    hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                    otherEntry_, i_, indicies_, portDomain_, 
                                    sourcePort_, destPort_, new_sport_, 
                                    depth_Pr, pkt_Pri, conn_Pr, hostMarker_Pri, 
                                    daddr_P, hostidx_P, hidx_Pr, otherEntry_P, 
                                    i_P, indicies_P, portDomain_P, 
                                    sourcePort_P, destPort_P, new_sport_P, 
                                    pkt_Priv, conn_Pri, hostMarker_Priv, 
                                    daddr_Pr, hostidx_Pr, hidx_Pri, 
                                    otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan41(self) == /\ pc[self] = "portscan41"
                    /\ PrintT(<<"SendQueue:", SendQueue, T>>)
                    /\ pc' = [pc EXCEPT ![self] = "portscan5_"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    stack, depth_, host_, hidx_, host_idx_, 
                                    pidx_, port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan5_(self) == /\ pc[self] = "portscan5_"
                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PubToPrivMan",
                                                             pc        |->  "portscan51",
                                                             pkt_P     |->  pkt_P[self],
                                                             ipkt_P    |->  ipkt_P[self],
                                                             entry_P   |->  entry_P[self],
                                                             conn_Pu   |->  conn_Pu[self],
                                                             hostMarker_P |->  hostMarker_P[self],
                                                             ip_idx_P  |->  ip_idx_P[self],
                                                             ipidx_P   |->  ipidx_P[self],
                                                             ip_Pu     |->  ip_Pu[self],
                                                             host_Pu   |->  host_Pu[self] ] >>
                                                         \o stack[self]]
                    /\ pkt_P' = [pkt_P EXCEPT ![self] = defaultInitValue]
                    /\ ipkt_P' = [ipkt_P EXCEPT ![self] = defaultInitValue]
                    /\ entry_P' = [entry_P EXCEPT ![self] = defaultInitValue]
                    /\ conn_Pu' = [conn_Pu EXCEPT ![self] = defaultInitValue]
                    /\ hostMarker_P' = [hostMarker_P EXCEPT ![self] = defaultInitValue]
                    /\ ip_idx_P' = [ip_idx_P EXCEPT ![self] = defaultInitValue]
                    /\ ipidx_P' = [ipidx_P EXCEPT ![self] = defaultInitValue]
                    /\ ip_Pu' = [ip_Pu EXCEPT ![self] = defaultInitValue]
                    /\ host_Pu' = [host_Pu EXCEPT ![self] = defaultInitValue]
                    /\ pc' = [pc EXCEPT ![self] = "pubtoprivManStart"]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

portscan51(self) == /\ pc[self] = "portscan51"
                    /\ PrintT(<<"SendQueue:", SendQueue, T>>)
                    /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                    /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

OldPortScan(self) == portscan1_(self) \/ portscan11(self)
                        \/ portscan2_(self) \/ portscan21(self)
                        \/ portscan3_(self) \/ portscan31(self)
                        \/ portscan4_(self) \/ portscan41(self)
                        \/ portscan5_(self) \/ portscan51(self)

evtSeqVStart(self) == /\ pc[self] = "evtSeqVStart"
                      /\ IF depth_E[self] <= 0
                            THEN /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                                 /\ i_E' = [i_E EXCEPT ![self] = Head(stack[self]).i_E]
                                 /\ j_' = [j_ EXCEPT ![self] = Head(stack[self]).j_]
                                 /\ ip_E' = [ip_E EXCEPT ![self] = Head(stack[self]).ip_E]
                                 /\ host_E' = [host_E EXCEPT ![self] = Head(stack[self]).host_E]
                                 /\ indecies_' = [indecies_ EXCEPT ![self] = Head(stack[self]).indecies_]
                                 /\ depth_E' = [depth_E EXCEPT ![self] = Head(stack[self]).depth_E]
                                 /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                                 /\ UNCHANGED << depth_, host_, hidx_, 
                                                 host_idx_, pidx_, port_idx_, 
                                                 depth_D, ip_, host_D, 
                                                 connDomain_, cidx_, conn_, 
                                                 depth_P, pkt_, ipkt_, entry_, 
                                                 conn_P, hostMarker_, ip_idx_, 
                                                 ipidx_, ip_P, host_P, 
                                                 depth_Pr, pkt_Pri, conn_Pr, 
                                                 hostMarker_Pri, daddr_P, 
                                                 hostidx_P, hidx_Pr, 
                                                 otherEntry_P, i_P, indicies_P, 
                                                 portDomain_P, sourcePort_P, 
                                                 destPort_P, new_sport_P >>
                            ELSE /\ \/ /\ IF Len(FreeIPs) > 0
                                             THEN /\ PrintT(<<"EventSequenceVuln - depth = ", depth_E[self]>>)
                                                  /\ /\ depth_' = [depth_ EXCEPT ![self] = depth_E[self] - 1]
                                                     /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "ConnectVuln",
                                                                                              pc        |->  "evtSeqVRet",
                                                                                              host_     |->  host_[self],
                                                                                              hidx_     |->  hidx_[self],
                                                                                              host_idx_ |->  host_idx_[self],
                                                                                              pidx_     |->  pidx_[self],
                                                                                              port_idx_ |->  port_idx_[self],
                                                                                              depth_    |->  depth_[self] ] >>
                                                                                          \o stack[self]]
                                                  /\ host_' = [host_ EXCEPT ![self] = defaultInitValue]
                                                  /\ hidx_' = [hidx_ EXCEPT ![self] = defaultInitValue]
                                                  /\ host_idx_' = [host_idx_ EXCEPT ![self] = defaultInitValue]
                                                  /\ pidx_' = [pidx_ EXCEPT ![self] = defaultInitValue]
                                                  /\ port_idx_' = [port_idx_ EXCEPT ![self] = defaultInitValue]
                                                  /\ pc' = [pc EXCEPT ![self] = "connectVEvtSeqV"]
                                             ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqVRet"]
                                                  /\ UNCHANGED << stack, 
                                                                  depth_, 
                                                                  host_, hidx_, 
                                                                  host_idx_, 
                                                                  pidx_, 
                                                                  port_idx_ >>
                                       /\ UNCHANGED <<depth_D, ip_, host_D, connDomain_, cidx_, conn_, depth_P, pkt_, ipkt_, entry_, conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, host_P, depth_Pr, pkt_Pri, conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, hidx_Pr, otherEntry_P, i_P, indicies_P, portDomain_P, sourcePort_P, destPort_P, new_sport_P>>
                                    \/ /\ IF Len (Connections) > 0
                                             THEN /\ PrintT(<<"EventSequenceVuln - Disconnect", Connections>>)
                                                  /\ /\ depth_D' = [depth_D EXCEPT ![self] = depth_E[self] - 1]
                                                     /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "DisconnectVuln",
                                                                                              pc        |->  "evtSeqVRet",
                                                                                              ip_       |->  ip_[self],
                                                                                              host_D    |->  host_D[self],
                                                                                              connDomain_ |->  connDomain_[self],
                                                                                              cidx_     |->  cidx_[self],
                                                                                              conn_     |->  conn_[self],
                                                                                              depth_D   |->  depth_D[self] ] >>
                                                                                          \o stack[self]]
                                                  /\ ip_' = [ip_ EXCEPT ![self] = defaultInitValue]
                                                  /\ host_D' = [host_D EXCEPT ![self] = defaultInitValue]
                                                  /\ connDomain_' = [connDomain_ EXCEPT ![self] = defaultInitValue]
                                                  /\ cidx_' = [cidx_ EXCEPT ![self] = defaultInitValue]
                                                  /\ conn_' = [conn_ EXCEPT ![self] = defaultInitValue]
                                                  /\ pc' = [pc EXCEPT ![self] = "disconnectVEvtSV"]
                                             ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqVRet"]
                                                  /\ UNCHANGED << stack, 
                                                                  depth_D, ip_, 
                                                                  host_D, 
                                                                  connDomain_, 
                                                                  cidx_, conn_ >>
                                       /\ UNCHANGED <<depth_, host_, hidx_, host_idx_, pidx_, port_idx_, depth_P, pkt_, ipkt_, entry_, conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, host_P, depth_Pr, pkt_Pri, conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, hidx_Pr, otherEntry_P, i_P, indicies_P, portDomain_P, sourcePort_P, destPort_P, new_sport_P>>
                                    \/ /\ IF Len(Connections) > 0
                                             THEN /\ PrintT(<<"EventSequenceVuln - PrivToPubVuln:", Connections>>)
                                                  /\ /\ depth_Pr' = [depth_Pr EXCEPT ![self] = depth_E[self] - 1]
                                                     /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PrivToPubVuln",
                                                                                              pc        |->  "evtSeqVRet",
                                                                                              pkt_Pri   |->  pkt_Pri[self],
                                                                                              conn_Pr   |->  conn_Pr[self],
                                                                                              hostMarker_Pri |->  hostMarker_Pri[self],
                                                                                              daddr_P   |->  daddr_P[self],
                                                                                              hostidx_P |->  hostidx_P[self],
                                                                                              hidx_Pr   |->  hidx_Pr[self],
                                                                                              otherEntry_P |->  otherEntry_P[self],
                                                                                              i_P       |->  i_P[self],
                                                                                              indicies_P |->  indicies_P[self],
                                                                                              portDomain_P |->  portDomain_P[self],
                                                                                              sourcePort_P |->  sourcePort_P[self],
                                                                                              destPort_P |->  destPort_P[self],
                                                                                              new_sport_P |->  new_sport_P[self],
                                                                                              depth_Pr  |->  depth_Pr[self] ] >>
                                                                                          \o stack[self]]
                                                  /\ pkt_Pri' = [pkt_Pri EXCEPT ![self] = defaultInitValue]
                                                  /\ conn_Pr' = [conn_Pr EXCEPT ![self] = defaultInitValue]
                                                  /\ hostMarker_Pri' = [hostMarker_Pri EXCEPT ![self] = defaultInitValue]
                                                  /\ daddr_P' = [daddr_P EXCEPT ![self] = defaultInitValue]
                                                  /\ hostidx_P' = [hostidx_P EXCEPT ![self] = defaultInitValue]
                                                  /\ hidx_Pr' = [hidx_Pr EXCEPT ![self] = defaultInitValue]
                                                  /\ otherEntry_P' = [otherEntry_P EXCEPT ![self] = defaultInitValue]
                                                  /\ i_P' = [i_P EXCEPT ![self] = defaultInitValue]
                                                  /\ indicies_P' = [indicies_P EXCEPT ![self] = defaultInitValue]
                                                  /\ portDomain_P' = [portDomain_P EXCEPT ![self] = defaultInitValue]
                                                  /\ sourcePort_P' = [sourcePort_P EXCEPT ![self] = defaultInitValue]
                                                  /\ destPort_P' = [destPort_P EXCEPT ![self] = defaultInitValue]
                                                  /\ new_sport_P' = [new_sport_P EXCEPT ![self] = defaultInitValue]
                                                  /\ pc' = [pc EXCEPT ![self] = "privtopubV3"]
                                             ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqVRet"]
                                                  /\ UNCHANGED << stack, 
                                                                  depth_Pr, 
                                                                  pkt_Pri, 
                                                                  conn_Pr, 
                                                                  hostMarker_Pri, 
                                                                  daddr_P, 
                                                                  hostidx_P, 
                                                                  hidx_Pr, 
                                                                  otherEntry_P, 
                                                                  i_P, 
                                                                  indicies_P, 
                                                                  portDomain_P, 
                                                                  sourcePort_P, 
                                                                  destPort_P, 
                                                                  new_sport_P >>
                                       /\ UNCHANGED <<depth_, host_, hidx_, host_idx_, pidx_, port_idx_, depth_D, ip_, host_D, connDomain_, cidx_, conn_, depth_P, pkt_, ipkt_, entry_, conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, host_P>>
                                    \/ /\ IF Len(SendQueue) > 0
                                             THEN /\ PrintT(<<"EventSequenceVuln - PubToPrivVuln: depth - ", depth_E[self], SendQueue>>)
                                                  /\ /\ depth_P' = [depth_P EXCEPT ![self] = depth_E[self] - 1]
                                                     /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PubToPrivVuln",
                                                                                              pc        |->  "evtSeqVRet",
                                                                                              pkt_      |->  pkt_[self],
                                                                                              ipkt_     |->  ipkt_[self],
                                                                                              entry_    |->  entry_[self],
                                                                                              conn_P    |->  conn_P[self],
                                                                                              hostMarker_ |->  hostMarker_[self],
                                                                                              ip_idx_   |->  ip_idx_[self],
                                                                                              ipidx_    |->  ipidx_[self],
                                                                                              ip_P      |->  ip_P[self],
                                                                                              host_P    |->  host_P[self],
                                                                                              depth_P   |->  depth_P[self] ] >>
                                                                                          \o stack[self]]
                                                  /\ pkt_' = [pkt_ EXCEPT ![self] = defaultInitValue]
                                                  /\ ipkt_' = [ipkt_ EXCEPT ![self] = defaultInitValue]
                                                  /\ entry_' = [entry_ EXCEPT ![self] = defaultInitValue]
                                                  /\ conn_P' = [conn_P EXCEPT ![self] = defaultInitValue]
                                                  /\ hostMarker_' = [hostMarker_ EXCEPT ![self] = defaultInitValue]
                                                  /\ ip_idx_' = [ip_idx_ EXCEPT ![self] = defaultInitValue]
                                                  /\ ipidx_' = [ipidx_ EXCEPT ![self] = defaultInitValue]
                                                  /\ ip_P' = [ip_P EXCEPT ![self] = defaultInitValue]
                                                  /\ host_P' = [host_P EXCEPT ![self] = defaultInitValue]
                                                  /\ pc' = [pc EXCEPT ![self] = "pubtoprivVEvt3"]
                                             ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqVRet"]
                                                  /\ UNCHANGED << stack, 
                                                                  depth_P, 
                                                                  pkt_, ipkt_, 
                                                                  entry_, 
                                                                  conn_P, 
                                                                  hostMarker_, 
                                                                  ip_idx_, 
                                                                  ipidx_, ip_P, 
                                                                  host_P >>
                                       /\ UNCHANGED <<depth_, host_, hidx_, host_idx_, pidx_, port_idx_, depth_D, ip_, host_D, connDomain_, cidx_, conn_, depth_Pr, pkt_Pri, conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, hidx_Pr, otherEntry_P, i_P, indicies_P, portDomain_P, sourcePort_P, destPort_P, new_sport_P>>
                                 /\ UNCHANGED << depth_E, i_E, j_, ip_E, 
                                                 host_E, indecies_ >>
                      /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                      Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                      Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                      Zz, H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                      PortMap2, TableFull, EvictionReroute, 
                                      PortScanInv, MaxTableSize, hosts, 
                                      FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                      ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                      Connections, SendQueue, RcvQueue, MAX, 
                                      Marker1, Marker2, CmdConnect, 
                                      CmdDisconnect, PortSpaceFull, host_Co, 
                                      ip_C, hidx_C, host_idx_C, pidx_C, 
                                      port_idx_C, host_Dis, ip_Di, 
                                      connDomain_D, cidx_D, conn_D, host, ip, 
                                      connDomain_Di, cidx_Di, conn_Di, pkt_P, 
                                      ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                      ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                      sport, dstAddr, dport, pkt_Pr, 
                                      hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                      otherEntry_, i_, indicies_, portDomain_, 
                                      sourcePort_, destPort_, new_sport_, 
                                      pkt_Priv, conn_Pri, hostMarker_Priv, 
                                      daddr_Pr, hostidx_Pr, hidx_Pri, 
                                      otherEntry_Pr, i_Pr, indicies_Pr, 
                                      portDomain_Pr, sourcePort_Pr, 
                                      destPort_Pr, new_sport_Pr, depth_C, 
                                      host_C, hidx_Co, host_idx, pidx, 
                                      port_idx, depth_Di, ip_D, host_Di, 
                                      connDomain, cidx, conn_Dis, depth_Pu, 
                                      pkt_Pu, ipkt, entry, conn_Pub, 
                                      hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                      host_Pub, depth_Pri, pkt, conn_Priv, 
                                      hostMarker, daddr, hostidx, hidx, 
                                      otherEntry, i_Pri, indicies, portDomain, 
                                      sourcePort, destPort, new_sport, good, 
                                      depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                      i_C, i, aa >>

evtSeqVRet(self) == /\ pc[self] = "evtSeqVRet"
                    /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                    /\ i_E' = [i_E EXCEPT ![self] = Head(stack[self]).i_E]
                    /\ j_' = [j_ EXCEPT ![self] = Head(stack[self]).j_]
                    /\ ip_E' = [ip_E EXCEPT ![self] = Head(stack[self]).ip_E]
                    /\ host_E' = [host_E EXCEPT ![self] = Head(stack[self]).host_E]
                    /\ indecies_' = [indecies_ EXCEPT ![self] = Head(stack[self]).indecies_]
                    /\ depth_E' = [depth_E EXCEPT ![self] = Head(stack[self]).depth_E]
                    /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                    /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                    Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                    Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                    MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                    TableFull, EvictionReroute, PortScanInv, 
                                    MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                    Ports, ExtraPorts, ExtraExtraPorts, T, 
                                    FreeIPs, UsedIPs, Connections, SendQueue, 
                                    RcvQueue, MAX, Marker1, Marker2, 
                                    CmdConnect, CmdDisconnect, PortSpaceFull, 
                                    depth_, host_, hidx_, host_idx_, pidx_, 
                                    port_idx_, depth_D, ip_, host_D, 
                                    connDomain_, cidx_, conn_, host_Co, ip_C, 
                                    hidx_C, host_idx_C, pidx_C, port_idx_C, 
                                    host_Dis, ip_Di, connDomain_D, cidx_D, 
                                    conn_D, host, ip, connDomain_Di, cidx_Di, 
                                    conn_Di, depth_P, pkt_, ipkt_, entry_, 
                                    conn_P, hostMarker_, ip_idx_, ipidx_, ip_P, 
                                    host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                    hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                    host_Pu, conn, sport, dstAddr, dport, 
                                    pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                    hidx_P, otherEntry_, i_, indicies_, 
                                    portDomain_, sourcePort_, destPort_, 
                                    new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                    hostMarker_Pri, daddr_P, hostidx_P, 
                                    hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                    portDomain_P, sourcePort_P, destPort_P, 
                                    new_sport_P, pkt_Priv, conn_Pri, 
                                    hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                    hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                    portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                    new_sport_Pr, depth_C, host_C, hidx_Co, 
                                    host_idx, pidx, port_idx, depth_Di, ip_D, 
                                    host_Di, connDomain, cidx, conn_Dis, 
                                    depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                    hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                    host_Pub, depth_Pri, pkt, conn_Priv, 
                                    hostMarker, daddr, hostidx, hidx, 
                                    otherEntry, i_Pri, indicies, portDomain, 
                                    sourcePort, destPort, new_sport, good, 
                                    depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                    i_C, i, aa >>

EventSequenceVuln(self) == evtSeqVStart(self) \/ evtSeqVRet(self)

evtSeqStart(self) == /\ pc[self] = "evtSeqStart"
                     /\ IF depth[self] <= 0
                           THEN /\ pc' = [pc EXCEPT ![self] = "evtSeqD0"]
                                /\ UNCHANGED << stack, depth_C, host_C, 
                                                hidx_Co, host_idx, pidx, 
                                                port_idx, depth_Di, ip_D, 
                                                host_Di, connDomain, cidx, 
                                                conn_Dis, depth_Pu, pkt_Pu, 
                                                ipkt, entry, conn_Pub, 
                                                hostMarker_Pu, ip_idx, ipidx, 
                                                ip_Pub, host_Pub, depth_Pri, 
                                                pkt, conn_Priv, hostMarker, 
                                                daddr, hostidx, hidx, 
                                                otherEntry, i_Pri, indicies, 
                                                portDomain, sourcePort, 
                                                destPort, new_sport, good >>
                           ELSE /\ \/ /\ IF Len(FreeIPs) > 0
                                            THEN /\ /\ depth_C' = [depth_C EXCEPT ![self] = depth[self] - 1]
                                                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "Connect",
                                                                                             pc        |->  "evtSeqRet",
                                                                                             host_C    |->  host_C[self],
                                                                                             hidx_Co   |->  hidx_Co[self],
                                                                                             host_idx  |->  host_idx[self],
                                                                                             pidx      |->  pidx[self],
                                                                                             port_idx  |->  port_idx[self],
                                                                                             depth_C   |->  depth_C[self] ] >>
                                                                                         \o stack[self]]
                                                 /\ host_C' = [host_C EXCEPT ![self] = defaultInitValue]
                                                 /\ hidx_Co' = [hidx_Co EXCEPT ![self] = defaultInitValue]
                                                 /\ host_idx' = [host_idx EXCEPT ![self] = defaultInitValue]
                                                 /\ pidx' = [pidx EXCEPT ![self] = defaultInitValue]
                                                 /\ port_idx' = [port_idx EXCEPT ![self] = defaultInitValue]
                                                 /\ pc' = [pc EXCEPT ![self] = "connectStart"]
                                            ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqRet"]
                                                 /\ UNCHANGED << stack, 
                                                                 depth_C, 
                                                                 host_C, 
                                                                 hidx_Co, 
                                                                 host_idx, 
                                                                 pidx, 
                                                                 port_idx >>
                                      /\ UNCHANGED <<depth_Di, ip_D, host_Di, connDomain, cidx, conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, hostMarker_Pu, ip_idx, ipidx, ip_Pub, host_Pub, depth_Pri, pkt, conn_Priv, hostMarker, daddr, hostidx, hidx, otherEntry, i_Pri, indicies, portDomain, sourcePort, destPort, new_sport, good>>
                                   \/ /\ IF Len (Connections) > 0
                                            THEN /\ /\ depth_Di' = [depth_Di EXCEPT ![self] = depth[self] - 1]
                                                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "Disconnect",
                                                                                             pc        |->  "evtSeqRet",
                                                                                             ip_D      |->  ip_D[self],
                                                                                             host_Di   |->  host_Di[self],
                                                                                             connDomain |->  connDomain[self],
                                                                                             cidx      |->  cidx[self],
                                                                                             conn_Dis  |->  conn_Dis[self],
                                                                                             depth_Di  |->  depth_Di[self] ] >>
                                                                                         \o stack[self]]
                                                 /\ ip_D' = [ip_D EXCEPT ![self] = defaultInitValue]
                                                 /\ host_Di' = [host_Di EXCEPT ![self] = defaultInitValue]
                                                 /\ connDomain' = [connDomain EXCEPT ![self] = defaultInitValue]
                                                 /\ cidx' = [cidx EXCEPT ![self] = defaultInitValue]
                                                 /\ conn_Dis' = [conn_Dis EXCEPT ![self] = defaultInitValue]
                                                 /\ pc' = [pc EXCEPT ![self] = "disconnectStart"]
                                            ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqRet"]
                                                 /\ UNCHANGED << stack, 
                                                                 depth_Di, 
                                                                 ip_D, host_Di, 
                                                                 connDomain, 
                                                                 cidx, 
                                                                 conn_Dis >>
                                      /\ UNCHANGED <<depth_C, host_C, hidx_Co, host_idx, pidx, port_idx, depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, hostMarker_Pu, ip_idx, ipidx, ip_Pub, host_Pub, depth_Pri, pkt, conn_Priv, hostMarker, daddr, hostidx, hidx, otherEntry, i_Pri, indicies, portDomain, sourcePort, destPort, new_sport, good>>
                                   \/ /\ IF Len(Connections) > 0
                                            THEN /\ /\ depth_Pri' = [depth_Pri EXCEPT ![self] = depth[self] - 1]
                                                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PrivToPub",
                                                                                             pc        |->  "evtSeqRet",
                                                                                             pkt       |->  pkt[self],
                                                                                             conn_Priv |->  conn_Priv[self],
                                                                                             hostMarker |->  hostMarker[self],
                                                                                             daddr     |->  daddr[self],
                                                                                             hostidx   |->  hostidx[self],
                                                                                             hidx      |->  hidx[self],
                                                                                             otherEntry |->  otherEntry[self],
                                                                                             i_Pri     |->  i_Pri[self],
                                                                                             indicies  |->  indicies[self],
                                                                                             portDomain |->  portDomain[self],
                                                                                             sourcePort |->  sourcePort[self],
                                                                                             destPort  |->  destPort[self],
                                                                                             new_sport |->  new_sport[self],
                                                                                             good      |->  good[self],
                                                                                             depth_Pri |->  depth_Pri[self] ] >>
                                                                                         \o stack[self]]
                                                 /\ pkt' = [pkt EXCEPT ![self] = defaultInitValue]
                                                 /\ conn_Priv' = [conn_Priv EXCEPT ![self] = defaultInitValue]
                                                 /\ hostMarker' = [hostMarker EXCEPT ![self] = defaultInitValue]
                                                 /\ daddr' = [daddr EXCEPT ![self] = defaultInitValue]
                                                 /\ hostidx' = [hostidx EXCEPT ![self] = defaultInitValue]
                                                 /\ hidx' = [hidx EXCEPT ![self] = defaultInitValue]
                                                 /\ otherEntry' = [otherEntry EXCEPT ![self] = defaultInitValue]
                                                 /\ i_Pri' = [i_Pri EXCEPT ![self] = defaultInitValue]
                                                 /\ indicies' = [indicies EXCEPT ![self] = defaultInitValue]
                                                 /\ portDomain' = [portDomain EXCEPT ![self] = defaultInitValue]
                                                 /\ sourcePort' = [sourcePort EXCEPT ![self] = defaultInitValue]
                                                 /\ destPort' = [destPort EXCEPT ![self] = defaultInitValue]
                                                 /\ new_sport' = [new_sport EXCEPT ![self] = defaultInitValue]
                                                 /\ good' = [good EXCEPT ![self] = defaultInitValue]
                                                 /\ pc' = [pc EXCEPT ![self] = "privtopubStart"]
                                            ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqRet"]
                                                 /\ UNCHANGED << stack, 
                                                                 depth_Pri, 
                                                                 pkt, 
                                                                 conn_Priv, 
                                                                 hostMarker, 
                                                                 daddr, 
                                                                 hostidx, hidx, 
                                                                 otherEntry, 
                                                                 i_Pri, 
                                                                 indicies, 
                                                                 portDomain, 
                                                                 sourcePort, 
                                                                 destPort, 
                                                                 new_sport, 
                                                                 good >>
                                      /\ UNCHANGED <<depth_C, host_C, hidx_Co, host_idx, pidx, port_idx, depth_Di, ip_D, host_Di, connDomain, cidx, conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, hostMarker_Pu, ip_idx, ipidx, ip_Pub, host_Pub>>
                                   \/ /\ IF Len(SendQueue) > 0
                                            THEN /\ /\ depth_Pu' = [depth_Pu EXCEPT ![self] = depth[self] - 1]
                                                    /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PubToPriv",
                                                                                             pc        |->  "evtSeqRet",
                                                                                             pkt_Pu    |->  pkt_Pu[self],
                                                                                             ipkt      |->  ipkt[self],
                                                                                             entry     |->  entry[self],
                                                                                             conn_Pub  |->  conn_Pub[self],
                                                                                             hostMarker_Pu |->  hostMarker_Pu[self],
                                                                                             ip_idx    |->  ip_idx[self],
                                                                                             ipidx     |->  ipidx[self],
                                                                                             ip_Pub    |->  ip_Pub[self],
                                                                                             host_Pub  |->  host_Pub[self],
                                                                                             depth_Pu  |->  depth_Pu[self] ] >>
                                                                                         \o stack[self]]
                                                 /\ pkt_Pu' = [pkt_Pu EXCEPT ![self] = defaultInitValue]
                                                 /\ ipkt' = [ipkt EXCEPT ![self] = defaultInitValue]
                                                 /\ entry' = [entry EXCEPT ![self] = defaultInitValue]
                                                 /\ conn_Pub' = [conn_Pub EXCEPT ![self] = defaultInitValue]
                                                 /\ hostMarker_Pu' = [hostMarker_Pu EXCEPT ![self] = defaultInitValue]
                                                 /\ ip_idx' = [ip_idx EXCEPT ![self] = defaultInitValue]
                                                 /\ ipidx' = [ipidx EXCEPT ![self] = defaultInitValue]
                                                 /\ ip_Pub' = [ip_Pub EXCEPT ![self] = defaultInitValue]
                                                 /\ host_Pub' = [host_Pub EXCEPT ![self] = defaultInitValue]
                                                 /\ pc' = [pc EXCEPT ![self] = "pubtoprivStart"]
                                            ELSE /\ pc' = [pc EXCEPT ![self] = "evtSeqRet"]
                                                 /\ UNCHANGED << stack, 
                                                                 depth_Pu, 
                                                                 pkt_Pu, ipkt, 
                                                                 entry, 
                                                                 conn_Pub, 
                                                                 hostMarker_Pu, 
                                                                 ip_idx, ipidx, 
                                                                 ip_Pub, 
                                                                 host_Pub >>
                                      /\ UNCHANGED <<depth_C, host_C, hidx_Co, host_idx, pidx, port_idx, depth_Di, ip_D, host_Di, connDomain, cidx, conn_Dis, depth_Pri, pkt, conn_Priv, hostMarker, daddr, hostidx, hidx, otherEntry, i_Pri, indicies, portDomain, sourcePort, destPort, new_sport, good>>
                     /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                     Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, 
                                     Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, 
                                     H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                                     PortMap2, TableFull, EvictionReroute, 
                                     PortScanInv, MaxTableSize, hosts, 
                                     FreeHosts, UsedHosts, Ports, ExtraPorts, 
                                     ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                     Connections, SendQueue, RcvQueue, MAX, 
                                     Marker1, Marker2, CmdConnect, 
                                     CmdDisconnect, PortSpaceFull, depth_, 
                                     host_, hidx_, host_idx_, pidx_, port_idx_, 
                                     depth_D, ip_, host_D, connDomain_, cidx_, 
                                     conn_, host_Co, ip_C, hidx_C, host_idx_C, 
                                     pidx_C, port_idx_C, host_Dis, ip_Di, 
                                     connDomain_D, cidx_D, conn_D, host, ip, 
                                     connDomain_Di, cidx_Di, conn_Di, depth_P, 
                                     pkt_, ipkt_, entry_, conn_P, hostMarker_, 
                                     ip_idx_, ipidx_, ip_P, host_P, pkt_P, 
                                     ipkt_P, entry_P, conn_Pu, hostMarker_P, 
                                     ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                                     sport, dstAddr, dport, pkt_Pr, 
                                     hostMarker_Pr, daddr_, hostidx_, hidx_P, 
                                     otherEntry_, i_, indicies_, portDomain_, 
                                     sourcePort_, destPort_, new_sport_, 
                                     depth_Pr, pkt_Pri, conn_Pr, 
                                     hostMarker_Pri, daddr_P, hostidx_P, 
                                     hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                     portDomain_P, sourcePort_P, destPort_P, 
                                     new_sport_P, pkt_Priv, conn_Pri, 
                                     hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                     hidx_Pri, otherEntry_Pr, i_Pr, 
                                     indicies_Pr, portDomain_Pr, sourcePort_Pr, 
                                     destPort_Pr, new_sport_Pr, depth_E, i_E, 
                                     j_, ip_E, host_E, indecies_, depth, i_Ev, 
                                     j, ip_Ev, host_Ev, indecies, i_C, i, aa >>

evtSeqD0(self) == /\ pc[self] = "evtSeqD0"
                  /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                  /\ i_Ev' = [i_Ev EXCEPT ![self] = Head(stack[self]).i_Ev]
                  /\ j' = [j EXCEPT ![self] = Head(stack[self]).j]
                  /\ ip_Ev' = [ip_Ev EXCEPT ![self] = Head(stack[self]).ip_Ev]
                  /\ host_Ev' = [host_Ev EXCEPT ![self] = Head(stack[self]).host_Ev]
                  /\ indecies' = [indecies EXCEPT ![self] = Head(stack[self]).indecies]
                  /\ depth' = [depth EXCEPT ![self] = Head(stack[self]).depth]
                  /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                  /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                  Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                  Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                  MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                  TableFull, EvictionReroute, PortScanInv, 
                                  MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                  Ports, ExtraPorts, ExtraExtraPorts, T, 
                                  FreeIPs, UsedIPs, Connections, SendQueue, 
                                  RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                  CmdDisconnect, PortSpaceFull, depth_, host_, 
                                  hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                  ip_, host_D, connDomain_, cidx_, conn_, 
                                  host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                  port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                  cidx_D, conn_D, host, ip, connDomain_Di, 
                                  cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                  entry_, conn_P, hostMarker_, ip_idx_, ipidx_, 
                                  ip_P, host_P, pkt_P, ipkt_P, entry_P, 
                                  conn_Pu, hostMarker_P, ip_idx_P, ipidx_P, 
                                  ip_Pu, host_Pu, conn, sport, dstAddr, dport, 
                                  pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                  hidx_P, otherEntry_, i_, indicies_, 
                                  portDomain_, sourcePort_, destPort_, 
                                  new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                  hostMarker_Pri, daddr_P, hostidx_P, hidx_Pr, 
                                  otherEntry_P, i_P, indicies_P, portDomain_P, 
                                  sourcePort_P, destPort_P, new_sport_P, 
                                  pkt_Priv, conn_Pri, hostMarker_Priv, 
                                  daddr_Pr, hostidx_Pr, hidx_Pri, 
                                  otherEntry_Pr, i_Pr, indicies_Pr, 
                                  portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                  new_sport_Pr, depth_C, host_C, hidx_Co, 
                                  host_idx, pidx, port_idx, depth_Di, ip_D, 
                                  host_Di, connDomain, cidx, conn_Dis, 
                                  depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                  hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                  host_Pub, depth_Pri, pkt, conn_Priv, 
                                  hostMarker, daddr, hostidx, hidx, otherEntry, 
                                  i_Pri, indicies, portDomain, sourcePort, 
                                  destPort, new_sport, good, depth_E, i_E, j_, 
                                  ip_E, host_E, indecies_, i_C, i, aa >>

evtSeqRet(self) == /\ pc[self] = "evtSeqRet"
                   /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                   /\ i_Ev' = [i_Ev EXCEPT ![self] = Head(stack[self]).i_Ev]
                   /\ j' = [j EXCEPT ![self] = Head(stack[self]).j]
                   /\ ip_Ev' = [ip_Ev EXCEPT ![self] = Head(stack[self]).ip_Ev]
                   /\ host_Ev' = [host_Ev EXCEPT ![self] = Head(stack[self]).host_Ev]
                   /\ indecies' = [indecies EXCEPT ![self] = Head(stack[self]).indecies]
                   /\ depth' = [depth EXCEPT ![self] = Head(stack[self]).depth]
                   /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                   /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                   Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                   Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                   MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                   TableFull, EvictionReroute, PortScanInv, 
                                   MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                   Ports, ExtraPorts, ExtraExtraPorts, T, 
                                   FreeIPs, UsedIPs, Connections, SendQueue, 
                                   RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                   CmdDisconnect, PortSpaceFull, depth_, host_, 
                                   hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                   ip_, host_D, connDomain_, cidx_, conn_, 
                                   host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                   port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                   cidx_D, conn_D, host, ip, connDomain_Di, 
                                   cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                   entry_, conn_P, hostMarker_, ip_idx_, 
                                   ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                   entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                   ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                   dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                   daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                   indicies_, portDomain_, sourcePort_, 
                                   destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                   conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, 
                                   hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                   portDomain_P, sourcePort_P, destPort_P, 
                                   new_sport_P, pkt_Priv, conn_Pri, 
                                   hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                   hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                   portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                   new_sport_Pr, depth_C, host_C, hidx_Co, 
                                   host_idx, pidx, port_idx, depth_Di, ip_D, 
                                   host_Di, connDomain, cidx, conn_Dis, 
                                   depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                   hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                   host_Pub, depth_Pri, pkt, conn_Priv, 
                                   hostMarker, daddr, hostidx, hidx, 
                                   otherEntry, i_Pri, indicies, portDomain, 
                                   sourcePort, destPort, new_sport, good, 
                                   depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                   i_C, i, aa >>

EventSequence(self) == evtSeqStart(self) \/ evtSeqD0(self)
                          \/ evtSeqRet(self)

checkModelStart(self) == /\ pc[self] = "checkModelStart"
                         /\ i_C' = [i_C EXCEPT ![self] = 0]
                         /\ pc' = [pc EXCEPT ![self] = "checkModelWhile"]
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                         Connections, SendQueue, RcvQueue, MAX, 
                                         Marker1, Marker2, CmdConnect, 
                                         CmdDisconnect, PortSpaceFull, stack, 
                                         depth_, host_, hidx_, host_idx_, 
                                         pidx_, port_idx_, depth_D, ip_, 
                                         host_D, connDomain_, cidx_, conn_, 
                                         host_Co, ip_C, hidx_C, host_idx_C, 
                                         pidx_C, port_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, pkt_Pri, conn_Pr, 
                                         hostMarker_Pri, daddr_P, hostidx_P, 
                                         hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth_E, i_E, j_, 
                                         ip_E, host_E, indecies_, depth, i_Ev, 
                                         j, ip_Ev, host_Ev, indecies, i, aa >>

checkModelWhile(self) == /\ pc[self] = "checkModelWhile"
                         /\ IF i_C[self] < MAX
                               THEN /\ /\ depth' = [depth EXCEPT ![self] = MAX]
                                       /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequence",
                                                                                pc        |->  "checkModelInc",
                                                                                i_Ev      |->  i_Ev[self],
                                                                                j         |->  j[self],
                                                                                ip_Ev     |->  ip_Ev[self],
                                                                                host_Ev   |->  host_Ev[self],
                                                                                indecies  |->  indecies[self],
                                                                                depth     |->  depth[self] ] >>
                                                                            \o stack[self]]
                                    /\ i_Ev' = [i_Ev EXCEPT ![self] = defaultInitValue]
                                    /\ j' = [j EXCEPT ![self] = defaultInitValue]
                                    /\ ip_Ev' = [ip_Ev EXCEPT ![self] = defaultInitValue]
                                    /\ host_Ev' = [host_Ev EXCEPT ![self] = defaultInitValue]
                                    /\ indecies' = [indecies EXCEPT ![self] = defaultInitValue]
                                    /\ pc' = [pc EXCEPT ![self] = "evtSeqStart"]
                               ELSE /\ pc' = [pc EXCEPT ![self] = "checkModelRet"]
                                    /\ UNCHANGED << stack, depth, i_Ev, j, 
                                                    ip_Ev, host_Ev, indecies >>
                         /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                         Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, 
                                         Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                                         Xx, Yy, Zz, H1, H2, MaxPorts, EP1, 
                                         PortMap1, EP2, PortMap2, TableFull, 
                                         EvictionReroute, PortScanInv, 
                                         MaxTableSize, hosts, FreeHosts, 
                                         UsedHosts, Ports, ExtraPorts, 
                                         ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                         Connections, SendQueue, RcvQueue, MAX, 
                                         Marker1, Marker2, CmdConnect, 
                                         CmdDisconnect, PortSpaceFull, depth_, 
                                         host_, hidx_, host_idx_, pidx_, 
                                         port_idx_, depth_D, ip_, host_D, 
                                         connDomain_, cidx_, conn_, host_Co, 
                                         ip_C, hidx_C, host_idx_C, pidx_C, 
                                         port_idx_C, host_Dis, ip_Di, 
                                         connDomain_D, cidx_D, conn_D, host, 
                                         ip, connDomain_Di, cidx_Di, conn_Di, 
                                         depth_P, pkt_, ipkt_, entry_, conn_P, 
                                         hostMarker_, ip_idx_, ipidx_, ip_P, 
                                         host_P, pkt_P, ipkt_P, entry_P, 
                                         conn_Pu, hostMarker_P, ip_idx_P, 
                                         ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                         dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                         daddr_, hostidx_, hidx_P, otherEntry_, 
                                         i_, indicies_, portDomain_, 
                                         sourcePort_, destPort_, new_sport_, 
                                         depth_Pr, pkt_Pri, conn_Pr, 
                                         hostMarker_Pri, daddr_P, hostidx_P, 
                                         hidx_Pr, otherEntry_P, i_P, 
                                         indicies_P, portDomain_P, 
                                         sourcePort_P, destPort_P, new_sport_P, 
                                         pkt_Priv, conn_Pri, hostMarker_Priv, 
                                         daddr_Pr, hostidx_Pr, hidx_Pri, 
                                         otherEntry_Pr, i_Pr, indicies_Pr, 
                                         portDomain_Pr, sourcePort_Pr, 
                                         destPort_Pr, new_sport_Pr, depth_C, 
                                         host_C, hidx_Co, host_idx, pidx, 
                                         port_idx, depth_Di, ip_D, host_Di, 
                                         connDomain, cidx, conn_Dis, depth_Pu, 
                                         pkt_Pu, ipkt, entry, conn_Pub, 
                                         hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                         host_Pub, depth_Pri, pkt, conn_Priv, 
                                         hostMarker, daddr, hostidx, hidx, 
                                         otherEntry, i_Pri, indicies, 
                                         portDomain, sourcePort, destPort, 
                                         new_sport, good, depth_E, i_E, j_, 
                                         ip_E, host_E, indecies_, i_C, i, aa >>

checkModelInc(self) == /\ pc[self] = "checkModelInc"
                       /\ i_C' = [i_C EXCEPT ![self] = i_C[self] + 1]
                       /\ pc' = [pc EXCEPT ![self] = "checkModelWhile"]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, stack, 
                                       depth_, host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i, aa >>

checkModelRet(self) == /\ pc[self] = "checkModelRet"
                       /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                       /\ i_C' = [i_C EXCEPT ![self] = Head(stack[self]).i_C]
                       /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                       /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, 
                                       Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, 
                                       Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, 
                                       Zz, H1, H2, MaxPorts, EP1, PortMap1, 
                                       EP2, PortMap2, TableFull, 
                                       EvictionReroute, PortScanInv, 
                                       MaxTableSize, hosts, FreeHosts, 
                                       UsedHosts, Ports, ExtraPorts, 
                                       ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                                       Connections, SendQueue, RcvQueue, MAX, 
                                       Marker1, Marker2, CmdConnect, 
                                       CmdDisconnect, PortSpaceFull, depth_, 
                                       host_, hidx_, host_idx_, pidx_, 
                                       port_idx_, depth_D, ip_, host_D, 
                                       connDomain_, cidx_, conn_, host_Co, 
                                       ip_C, hidx_C, host_idx_C, pidx_C, 
                                       port_idx_C, host_Dis, ip_Di, 
                                       connDomain_D, cidx_D, conn_D, host, ip, 
                                       connDomain_Di, cidx_Di, conn_Di, 
                                       depth_P, pkt_, ipkt_, entry_, conn_P, 
                                       hostMarker_, ip_idx_, ipidx_, ip_P, 
                                       host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                                       hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, 
                                       host_Pu, conn, sport, dstAddr, dport, 
                                       pkt_Pr, hostMarker_Pr, daddr_, hostidx_, 
                                       hidx_P, otherEntry_, i_, indicies_, 
                                       portDomain_, sourcePort_, destPort_, 
                                       new_sport_, depth_Pr, pkt_Pri, conn_Pr, 
                                       hostMarker_Pri, daddr_P, hostidx_P, 
                                       hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                       portDomain_P, sourcePort_P, destPort_P, 
                                       new_sport_P, pkt_Priv, conn_Pri, 
                                       hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                       hidx_Pri, otherEntry_Pr, i_Pr, 
                                       indicies_Pr, portDomain_Pr, 
                                       sourcePort_Pr, destPort_Pr, 
                                       new_sport_Pr, depth_C, host_C, hidx_Co, 
                                       host_idx, pidx, port_idx, depth_Di, 
                                       ip_D, host_Di, connDomain, cidx, 
                                       conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, 
                                       conn_Pub, hostMarker_Pu, ip_idx, ipidx, 
                                       ip_Pub, host_Pub, depth_Pri, pkt, 
                                       conn_Priv, hostMarker, daddr, hostidx, 
                                       hidx, otherEntry, i_Pri, indicies, 
                                       portDomain, sourcePort, destPort, 
                                       new_sport, good, depth_E, i_E, j_, ip_E, 
                                       host_E, indecies_, depth, i_Ev, j, 
                                       ip_Ev, host_Ev, indecies, i, aa >>

CheckModel(self) == checkModelStart(self) \/ checkModelWhile(self)
                       \/ checkModelInc(self) \/ checkModelRet(self)

checkModelVulnStart(self) == /\ pc[self] = "checkModelVulnStart"
                             /\ i' = [i EXCEPT ![self] = 0]
                             /\ pc' = [pc EXCEPT ![self] = "checkModelVulnWhile"]
                             /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                             Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, 
                                             Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, 
                                             Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                             MaxPorts, EP1, PortMap1, EP2, 
                                             PortMap2, TableFull, 
                                             EvictionReroute, PortScanInv, 
                                             MaxTableSize, hosts, FreeHosts, 
                                             UsedHosts, Ports, ExtraPorts, 
                                             ExtraExtraPorts, T, FreeIPs, 
                                             UsedIPs, Connections, SendQueue, 
                                             RcvQueue, MAX, Marker1, Marker2, 
                                             CmdConnect, CmdDisconnect, 
                                             PortSpaceFull, stack, depth_, 
                                             host_, hidx_, host_idx_, pidx_, 
                                             port_idx_, depth_D, ip_, host_D, 
                                             connDomain_, cidx_, conn_, 
                                             host_Co, ip_C, hidx_C, host_idx_C, 
                                             pidx_C, port_idx_C, host_Dis, 
                                             ip_Di, connDomain_D, cidx_D, 
                                             conn_D, host, ip, connDomain_Di, 
                                             cidx_Di, conn_Di, depth_P, pkt_, 
                                             ipkt_, entry_, conn_P, 
                                             hostMarker_, ip_idx_, ipidx_, 
                                             ip_P, host_P, pkt_P, ipkt_P, 
                                             entry_P, conn_Pu, hostMarker_P, 
                                             ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                             conn, sport, dstAddr, dport, 
                                             pkt_Pr, hostMarker_Pr, daddr_, 
                                             hostidx_, hidx_P, otherEntry_, i_, 
                                             indicies_, portDomain_, 
                                             sourcePort_, destPort_, 
                                             new_sport_, depth_Pr, pkt_Pri, 
                                             conn_Pr, hostMarker_Pri, daddr_P, 
                                             hostidx_P, hidx_Pr, otherEntry_P, 
                                             i_P, indicies_P, portDomain_P, 
                                             sourcePort_P, destPort_P, 
                                             new_sport_P, pkt_Priv, conn_Pri, 
                                             hostMarker_Priv, daddr_Pr, 
                                             hostidx_Pr, hidx_Pri, 
                                             otherEntry_Pr, i_Pr, indicies_Pr, 
                                             portDomain_Pr, sourcePort_Pr, 
                                             destPort_Pr, new_sport_Pr, 
                                             depth_C, host_C, hidx_Co, 
                                             host_idx, pidx, port_idx, 
                                             depth_Di, ip_D, host_Di, 
                                             connDomain, cidx, conn_Dis, 
                                             depth_Pu, pkt_Pu, ipkt, entry, 
                                             conn_Pub, hostMarker_Pu, ip_idx, 
                                             ipidx, ip_Pub, host_Pub, 
                                             depth_Pri, pkt, conn_Priv, 
                                             hostMarker, daddr, hostidx, hidx, 
                                             otherEntry, i_Pri, indicies, 
                                             portDomain, sourcePort, destPort, 
                                             new_sport, good, depth_E, i_E, j_, 
                                             ip_E, host_E, indecies_, depth, 
                                             i_Ev, j, ip_Ev, host_Ev, indecies, 
                                             i_C, aa >>

checkModelVulnWhile(self) == /\ pc[self] = "checkModelVulnWhile"
                             /\ IF i[self] < MAX
                                   THEN /\ /\ depth_E' = [depth_E EXCEPT ![self] = MAX]
                                           /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "EventSequenceVuln",
                                                                                    pc        |->  "checkModelVulnInc",
                                                                                    i_E       |->  i_E[self],
                                                                                    j_        |->  j_[self],
                                                                                    ip_E      |->  ip_E[self],
                                                                                    host_E    |->  host_E[self],
                                                                                    indecies_ |->  indecies_[self],
                                                                                    depth_E   |->  depth_E[self] ] >>
                                                                                \o stack[self]]
                                        /\ i_E' = [i_E EXCEPT ![self] = defaultInitValue]
                                        /\ j_' = [j_ EXCEPT ![self] = defaultInitValue]
                                        /\ ip_E' = [ip_E EXCEPT ![self] = defaultInitValue]
                                        /\ host_E' = [host_E EXCEPT ![self] = defaultInitValue]
                                        /\ indecies_' = [indecies_ EXCEPT ![self] = defaultInitValue]
                                        /\ pc' = [pc EXCEPT ![self] = "evtSeqVStart"]
                                   ELSE /\ pc' = [pc EXCEPT ![self] = "checkModelVulnRet"]
                                        /\ UNCHANGED << stack, depth_E, i_E, 
                                                        j_, ip_E, host_E, 
                                                        indecies_ >>
                             /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                             Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, 
                                             Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, 
                                             Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                             MaxPorts, EP1, PortMap1, EP2, 
                                             PortMap2, TableFull, 
                                             EvictionReroute, PortScanInv, 
                                             MaxTableSize, hosts, FreeHosts, 
                                             UsedHosts, Ports, ExtraPorts, 
                                             ExtraExtraPorts, T, FreeIPs, 
                                             UsedIPs, Connections, SendQueue, 
                                             RcvQueue, MAX, Marker1, Marker2, 
                                             CmdConnect, CmdDisconnect, 
                                             PortSpaceFull, depth_, host_, 
                                             hidx_, host_idx_, pidx_, 
                                             port_idx_, depth_D, ip_, host_D, 
                                             connDomain_, cidx_, conn_, 
                                             host_Co, ip_C, hidx_C, host_idx_C, 
                                             pidx_C, port_idx_C, host_Dis, 
                                             ip_Di, connDomain_D, cidx_D, 
                                             conn_D, host, ip, connDomain_Di, 
                                             cidx_Di, conn_Di, depth_P, pkt_, 
                                             ipkt_, entry_, conn_P, 
                                             hostMarker_, ip_idx_, ipidx_, 
                                             ip_P, host_P, pkt_P, ipkt_P, 
                                             entry_P, conn_Pu, hostMarker_P, 
                                             ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                             conn, sport, dstAddr, dport, 
                                             pkt_Pr, hostMarker_Pr, daddr_, 
                                             hostidx_, hidx_P, otherEntry_, i_, 
                                             indicies_, portDomain_, 
                                             sourcePort_, destPort_, 
                                             new_sport_, depth_Pr, pkt_Pri, 
                                             conn_Pr, hostMarker_Pri, daddr_P, 
                                             hostidx_P, hidx_Pr, otherEntry_P, 
                                             i_P, indicies_P, portDomain_P, 
                                             sourcePort_P, destPort_P, 
                                             new_sport_P, pkt_Priv, conn_Pri, 
                                             hostMarker_Priv, daddr_Pr, 
                                             hostidx_Pr, hidx_Pri, 
                                             otherEntry_Pr, i_Pr, indicies_Pr, 
                                             portDomain_Pr, sourcePort_Pr, 
                                             destPort_Pr, new_sport_Pr, 
                                             depth_C, host_C, hidx_Co, 
                                             host_idx, pidx, port_idx, 
                                             depth_Di, ip_D, host_Di, 
                                             connDomain, cidx, conn_Dis, 
                                             depth_Pu, pkt_Pu, ipkt, entry, 
                                             conn_Pub, hostMarker_Pu, ip_idx, 
                                             ipidx, ip_Pub, host_Pub, 
                                             depth_Pri, pkt, conn_Priv, 
                                             hostMarker, daddr, hostidx, hidx, 
                                             otherEntry, i_Pri, indicies, 
                                             portDomain, sourcePort, destPort, 
                                             new_sport, good, depth, i_Ev, j, 
                                             ip_Ev, host_Ev, indecies, i_C, i, 
                                             aa >>

checkModelVulnInc(self) == /\ pc[self] = "checkModelVulnInc"
                           /\ i' = [i EXCEPT ![self] = i[self] + 1]
                           /\ pc' = [pc EXCEPT ![self] = "checkModelVulnWhile"]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, T, 
                                           FreeIPs, UsedIPs, Connections, 
                                           SendQueue, RcvQueue, MAX, Marker1, 
                                           Marker2, CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, stack, depth_, host_, 
                                           hidx_, host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, conn_Pu, hostMarker_P, 
                                           ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                           conn, sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, aa >>

checkModelVulnRet(self) == /\ pc[self] = "checkModelVulnRet"
                           /\ pc' = [pc EXCEPT ![self] = Head(stack[self]).pc]
                           /\ i' = [i EXCEPT ![self] = Head(stack[self]).i]
                           /\ stack' = [stack EXCEPT ![self] = Tail(stack[self])]
                           /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, 
                                           Ee, Ff, Gg, Hh, Ii, Jj, Kk, Ll, Mm, 
                                           Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, 
                                           Ww, Xx, Yy, Zz, H1, H2, MaxPorts, 
                                           EP1, PortMap1, EP2, PortMap2, 
                                           TableFull, EvictionReroute, 
                                           PortScanInv, MaxTableSize, hosts, 
                                           FreeHosts, UsedHosts, Ports, 
                                           ExtraPorts, ExtraExtraPorts, T, 
                                           FreeIPs, UsedIPs, Connections, 
                                           SendQueue, RcvQueue, MAX, Marker1, 
                                           Marker2, CmdConnect, CmdDisconnect, 
                                           PortSpaceFull, depth_, host_, hidx_, 
                                           host_idx_, pidx_, port_idx_, 
                                           depth_D, ip_, host_D, connDomain_, 
                                           cidx_, conn_, host_Co, ip_C, hidx_C, 
                                           host_idx_C, pidx_C, port_idx_C, 
                                           host_Dis, ip_Di, connDomain_D, 
                                           cidx_D, conn_D, host, ip, 
                                           connDomain_Di, cidx_Di, conn_Di, 
                                           depth_P, pkt_, ipkt_, entry_, 
                                           conn_P, hostMarker_, ip_idx_, 
                                           ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                           entry_P, conn_Pu, hostMarker_P, 
                                           ip_idx_P, ipidx_P, ip_Pu, host_Pu, 
                                           conn, sport, dstAddr, dport, pkt_Pr, 
                                           hostMarker_Pr, daddr_, hostidx_, 
                                           hidx_P, otherEntry_, i_, indicies_, 
                                           portDomain_, sourcePort_, destPort_, 
                                           new_sport_, depth_Pr, pkt_Pri, 
                                           conn_Pr, hostMarker_Pri, daddr_P, 
                                           hostidx_P, hidx_Pr, otherEntry_P, 
                                           i_P, indicies_P, portDomain_P, 
                                           sourcePort_P, destPort_P, 
                                           new_sport_P, pkt_Priv, conn_Pri, 
                                           hostMarker_Priv, daddr_Pr, 
                                           hostidx_Pr, hidx_Pri, otherEntry_Pr, 
                                           i_Pr, indicies_Pr, portDomain_Pr, 
                                           sourcePort_Pr, destPort_Pr, 
                                           new_sport_Pr, depth_C, host_C, 
                                           hidx_Co, host_idx, pidx, port_idx, 
                                           depth_Di, ip_D, host_Di, connDomain, 
                                           cidx, conn_Dis, depth_Pu, pkt_Pu, 
                                           ipkt, entry, conn_Pub, 
                                           hostMarker_Pu, ip_idx, ipidx, 
                                           ip_Pub, host_Pub, depth_Pri, pkt, 
                                           conn_Priv, hostMarker, daddr, 
                                           hostidx, hidx, otherEntry, i_Pri, 
                                           indicies, portDomain, sourcePort, 
                                           destPort, new_sport, good, depth_E, 
                                           i_E, j_, ip_E, host_E, indecies_, 
                                           depth, i_Ev, j, ip_Ev, host_Ev, 
                                           indecies, i_C, aa >>

CheckModelVuln(self) == checkModelVulnStart(self)
                           \/ checkModelVulnWhile(self)
                           \/ checkModelVulnInc(self)
                           \/ checkModelVulnRet(self)

portscan1(self) == /\ pc[self] = "portscan1"
                   /\ /\ depth_C' = [depth_C EXCEPT ![self] = 0]
                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "Connect",
                                                               pc        |->  "portscan2",
                                                               host_C    |->  host_C[self],
                                                               hidx_Co   |->  hidx_Co[self],
                                                               host_idx  |->  host_idx[self],
                                                               pidx      |->  pidx[self],
                                                               port_idx  |->  port_idx[self],
                                                               depth_C   |->  depth_C[self] ] >>
                                                           \o stack[self]]
                   /\ host_C' = [host_C EXCEPT ![self] = defaultInitValue]
                   /\ hidx_Co' = [hidx_Co EXCEPT ![self] = defaultInitValue]
                   /\ host_idx' = [host_idx EXCEPT ![self] = defaultInitValue]
                   /\ pidx' = [pidx EXCEPT ![self] = defaultInitValue]
                   /\ port_idx' = [port_idx EXCEPT ![self] = defaultInitValue]
                   /\ pc' = [pc EXCEPT ![self] = "connectStart"]
                   /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                   Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                   Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                   MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                   TableFull, EvictionReroute, PortScanInv, 
                                   MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                   Ports, ExtraPorts, ExtraExtraPorts, T, 
                                   FreeIPs, UsedIPs, Connections, SendQueue, 
                                   RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                   CmdDisconnect, PortSpaceFull, depth_, host_, 
                                   hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                   ip_, host_D, connDomain_, cidx_, conn_, 
                                   host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                   port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                   cidx_D, conn_D, host, ip, connDomain_Di, 
                                   cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                   entry_, conn_P, hostMarker_, ip_idx_, 
                                   ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                   entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                   ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                   dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                   daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                   indicies_, portDomain_, sourcePort_, 
                                   destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                   conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, 
                                   hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                   portDomain_P, sourcePort_P, destPort_P, 
                                   new_sport_P, pkt_Priv, conn_Pri, 
                                   hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                   hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                   portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                   new_sport_Pr, depth_Di, ip_D, host_Di, 
                                   connDomain, cidx, conn_Dis, depth_Pu, 
                                   pkt_Pu, ipkt, entry, conn_Pub, 
                                   hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                   host_Pub, depth_Pri, pkt, conn_Priv, 
                                   hostMarker, daddr, hostidx, hidx, 
                                   otherEntry, i_Pri, indicies, portDomain, 
                                   sourcePort, destPort, new_sport, good, 
                                   depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                   depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                   i_C, i, aa >>

portscan2(self) == /\ pc[self] = "portscan2"
                   /\ /\ depth_Pri' = [depth_Pri EXCEPT ![self] = 0]
                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PrivToPub",
                                                               pc        |->  "portscan3",
                                                               pkt       |->  pkt[self],
                                                               conn_Priv |->  conn_Priv[self],
                                                               hostMarker |->  hostMarker[self],
                                                               daddr     |->  daddr[self],
                                                               hostidx   |->  hostidx[self],
                                                               hidx      |->  hidx[self],
                                                               otherEntry |->  otherEntry[self],
                                                               i_Pri     |->  i_Pri[self],
                                                               indicies  |->  indicies[self],
                                                               portDomain |->  portDomain[self],
                                                               sourcePort |->  sourcePort[self],
                                                               destPort  |->  destPort[self],
                                                               new_sport |->  new_sport[self],
                                                               good      |->  good[self],
                                                               depth_Pri |->  depth_Pri[self] ] >>
                                                           \o stack[self]]
                   /\ pkt' = [pkt EXCEPT ![self] = defaultInitValue]
                   /\ conn_Priv' = [conn_Priv EXCEPT ![self] = defaultInitValue]
                   /\ hostMarker' = [hostMarker EXCEPT ![self] = defaultInitValue]
                   /\ daddr' = [daddr EXCEPT ![self] = defaultInitValue]
                   /\ hostidx' = [hostidx EXCEPT ![self] = defaultInitValue]
                   /\ hidx' = [hidx EXCEPT ![self] = defaultInitValue]
                   /\ otherEntry' = [otherEntry EXCEPT ![self] = defaultInitValue]
                   /\ i_Pri' = [i_Pri EXCEPT ![self] = defaultInitValue]
                   /\ indicies' = [indicies EXCEPT ![self] = defaultInitValue]
                   /\ portDomain' = [portDomain EXCEPT ![self] = defaultInitValue]
                   /\ sourcePort' = [sourcePort EXCEPT ![self] = defaultInitValue]
                   /\ destPort' = [destPort EXCEPT ![self] = defaultInitValue]
                   /\ new_sport' = [new_sport EXCEPT ![self] = defaultInitValue]
                   /\ good' = [good EXCEPT ![self] = defaultInitValue]
                   /\ pc' = [pc EXCEPT ![self] = "privtopubStart"]
                   /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                   Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                   Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                   MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                   TableFull, EvictionReroute, PortScanInv, 
                                   MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                   Ports, ExtraPorts, ExtraExtraPorts, T, 
                                   FreeIPs, UsedIPs, Connections, SendQueue, 
                                   RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                   CmdDisconnect, PortSpaceFull, depth_, host_, 
                                   hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                   ip_, host_D, connDomain_, cidx_, conn_, 
                                   host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                   port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                   cidx_D, conn_D, host, ip, connDomain_Di, 
                                   cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                   entry_, conn_P, hostMarker_, ip_idx_, 
                                   ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                   entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                   ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                   dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                   daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                   indicies_, portDomain_, sourcePort_, 
                                   destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                   conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, 
                                   hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                   portDomain_P, sourcePort_P, destPort_P, 
                                   new_sport_P, pkt_Priv, conn_Pri, 
                                   hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                   hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                   portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                   new_sport_Pr, depth_C, host_C, hidx_Co, 
                                   host_idx, pidx, port_idx, depth_Di, ip_D, 
                                   host_Di, connDomain, cidx, conn_Dis, 
                                   depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                                   hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                   host_Pub, depth_E, i_E, j_, ip_E, host_E, 
                                   indecies_, depth, i_Ev, j, ip_Ev, host_Ev, 
                                   indecies, i_C, i, aa >>

portscan3(self) == /\ pc[self] = "portscan3"
                   /\ /\ depth_Di' = [depth_Di EXCEPT ![self] = 0]
                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "Disconnect",
                                                               pc        |->  "portscan4",
                                                               ip_D      |->  ip_D[self],
                                                               host_Di   |->  host_Di[self],
                                                               connDomain |->  connDomain[self],
                                                               cidx      |->  cidx[self],
                                                               conn_Dis  |->  conn_Dis[self],
                                                               depth_Di  |->  depth_Di[self] ] >>
                                                           \o stack[self]]
                   /\ ip_D' = [ip_D EXCEPT ![self] = defaultInitValue]
                   /\ host_Di' = [host_Di EXCEPT ![self] = defaultInitValue]
                   /\ connDomain' = [connDomain EXCEPT ![self] = defaultInitValue]
                   /\ cidx' = [cidx EXCEPT ![self] = defaultInitValue]
                   /\ conn_Dis' = [conn_Dis EXCEPT ![self] = defaultInitValue]
                   /\ pc' = [pc EXCEPT ![self] = "disconnectStart"]
                   /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                   Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                   Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                   MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                   TableFull, EvictionReroute, PortScanInv, 
                                   MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                   Ports, ExtraPorts, ExtraExtraPorts, T, 
                                   FreeIPs, UsedIPs, Connections, SendQueue, 
                                   RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                   CmdDisconnect, PortSpaceFull, depth_, host_, 
                                   hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                   ip_, host_D, connDomain_, cidx_, conn_, 
                                   host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                   port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                   cidx_D, conn_D, host, ip, connDomain_Di, 
                                   cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                   entry_, conn_P, hostMarker_, ip_idx_, 
                                   ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                   entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                   ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                   dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                   daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                   indicies_, portDomain_, sourcePort_, 
                                   destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                   conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, 
                                   hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                   portDomain_P, sourcePort_P, destPort_P, 
                                   new_sport_P, pkt_Priv, conn_Pri, 
                                   hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                   hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                   portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                   new_sport_Pr, depth_C, host_C, hidx_Co, 
                                   host_idx, pidx, port_idx, depth_Pu, pkt_Pu, 
                                   ipkt, entry, conn_Pub, hostMarker_Pu, 
                                   ip_idx, ipidx, ip_Pub, host_Pub, depth_Pri, 
                                   pkt, conn_Priv, hostMarker, daddr, hostidx, 
                                   hidx, otherEntry, i_Pri, indicies, 
                                   portDomain, sourcePort, destPort, new_sport, 
                                   good, depth_E, i_E, j_, ip_E, host_E, 
                                   indecies_, depth, i_Ev, j, ip_Ev, host_Ev, 
                                   indecies, i_C, i, aa >>

portscan4(self) == /\ pc[self] = "portscan4"
                   /\ /\ depth_C' = [depth_C EXCEPT ![self] = 0]
                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "Connect",
                                                               pc        |->  "portscan5",
                                                               host_C    |->  host_C[self],
                                                               hidx_Co   |->  hidx_Co[self],
                                                               host_idx  |->  host_idx[self],
                                                               pidx      |->  pidx[self],
                                                               port_idx  |->  port_idx[self],
                                                               depth_C   |->  depth_C[self] ] >>
                                                           \o stack[self]]
                   /\ host_C' = [host_C EXCEPT ![self] = defaultInitValue]
                   /\ hidx_Co' = [hidx_Co EXCEPT ![self] = defaultInitValue]
                   /\ host_idx' = [host_idx EXCEPT ![self] = defaultInitValue]
                   /\ pidx' = [pidx EXCEPT ![self] = defaultInitValue]
                   /\ port_idx' = [port_idx EXCEPT ![self] = defaultInitValue]
                   /\ pc' = [pc EXCEPT ![self] = "connectStart"]
                   /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                   Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                   Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                   MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                   TableFull, EvictionReroute, PortScanInv, 
                                   MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                   Ports, ExtraPorts, ExtraExtraPorts, T, 
                                   FreeIPs, UsedIPs, Connections, SendQueue, 
                                   RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                   CmdDisconnect, PortSpaceFull, depth_, host_, 
                                   hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                   ip_, host_D, connDomain_, cidx_, conn_, 
                                   host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                   port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                   cidx_D, conn_D, host, ip, connDomain_Di, 
                                   cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                   entry_, conn_P, hostMarker_, ip_idx_, 
                                   ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                   entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                   ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                   dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                   daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                   indicies_, portDomain_, sourcePort_, 
                                   destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                   conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, 
                                   hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                   portDomain_P, sourcePort_P, destPort_P, 
                                   new_sport_P, pkt_Priv, conn_Pri, 
                                   hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                   hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                   portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                   new_sport_Pr, depth_Di, ip_D, host_Di, 
                                   connDomain, cidx, conn_Dis, depth_Pu, 
                                   pkt_Pu, ipkt, entry, conn_Pub, 
                                   hostMarker_Pu, ip_idx, ipidx, ip_Pub, 
                                   host_Pub, depth_Pri, pkt, conn_Priv, 
                                   hostMarker, daddr, hostidx, hidx, 
                                   otherEntry, i_Pri, indicies, portDomain, 
                                   sourcePort, destPort, new_sport, good, 
                                   depth_E, i_E, j_, ip_E, host_E, indecies_, 
                                   depth, i_Ev, j, ip_Ev, host_Ev, indecies, 
                                   i_C, i, aa >>

portscan5(self) == /\ pc[self] = "portscan5"
                   /\ /\ depth_Pu' = [depth_Pu EXCEPT ![self] = 0]
                      /\ stack' = [stack EXCEPT ![self] = << [ procedure |->  "PubToPriv",
                                                               pc        |->  Head(stack[self]).pc,
                                                               pkt_Pu    |->  pkt_Pu[self],
                                                               ipkt      |->  ipkt[self],
                                                               entry     |->  entry[self],
                                                               conn_Pub  |->  conn_Pub[self],
                                                               hostMarker_Pu |->  hostMarker_Pu[self],
                                                               ip_idx    |->  ip_idx[self],
                                                               ipidx     |->  ipidx[self],
                                                               ip_Pub    |->  ip_Pub[self],
                                                               host_Pub  |->  host_Pub[self],
                                                               depth_Pu  |->  depth_Pu[self] ] >>
                                                           \o Tail(stack[self])]
                   /\ pkt_Pu' = [pkt_Pu EXCEPT ![self] = defaultInitValue]
                   /\ ipkt' = [ipkt EXCEPT ![self] = defaultInitValue]
                   /\ entry' = [entry EXCEPT ![self] = defaultInitValue]
                   /\ conn_Pub' = [conn_Pub EXCEPT ![self] = defaultInitValue]
                   /\ hostMarker_Pu' = [hostMarker_Pu EXCEPT ![self] = defaultInitValue]
                   /\ ip_idx' = [ip_idx EXCEPT ![self] = defaultInitValue]
                   /\ ipidx' = [ipidx EXCEPT ![self] = defaultInitValue]
                   /\ ip_Pub' = [ip_Pub EXCEPT ![self] = defaultInitValue]
                   /\ host_Pub' = [host_Pub EXCEPT ![self] = defaultInitValue]
                   /\ pc' = [pc EXCEPT ![self] = "pubtoprivStart"]
                   /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, 
                                   Gg, Hh, Ii, Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, 
                                   Rr, Ss, Tt, Uu, Vv, Ww, Xx, Yy, Zz, H1, H2, 
                                   MaxPorts, EP1, PortMap1, EP2, PortMap2, 
                                   TableFull, EvictionReroute, PortScanInv, 
                                   MaxTableSize, hosts, FreeHosts, UsedHosts, 
                                   Ports, ExtraPorts, ExtraExtraPorts, T, 
                                   FreeIPs, UsedIPs, Connections, SendQueue, 
                                   RcvQueue, MAX, Marker1, Marker2, CmdConnect, 
                                   CmdDisconnect, PortSpaceFull, depth_, host_, 
                                   hidx_, host_idx_, pidx_, port_idx_, depth_D, 
                                   ip_, host_D, connDomain_, cidx_, conn_, 
                                   host_Co, ip_C, hidx_C, host_idx_C, pidx_C, 
                                   port_idx_C, host_Dis, ip_Di, connDomain_D, 
                                   cidx_D, conn_D, host, ip, connDomain_Di, 
                                   cidx_Di, conn_Di, depth_P, pkt_, ipkt_, 
                                   entry_, conn_P, hostMarker_, ip_idx_, 
                                   ipidx_, ip_P, host_P, pkt_P, ipkt_P, 
                                   entry_P, conn_Pu, hostMarker_P, ip_idx_P, 
                                   ipidx_P, ip_Pu, host_Pu, conn, sport, 
                                   dstAddr, dport, pkt_Pr, hostMarker_Pr, 
                                   daddr_, hostidx_, hidx_P, otherEntry_, i_, 
                                   indicies_, portDomain_, sourcePort_, 
                                   destPort_, new_sport_, depth_Pr, pkt_Pri, 
                                   conn_Pr, hostMarker_Pri, daddr_P, hostidx_P, 
                                   hidx_Pr, otherEntry_P, i_P, indicies_P, 
                                   portDomain_P, sourcePort_P, destPort_P, 
                                   new_sport_P, pkt_Priv, conn_Pri, 
                                   hostMarker_Priv, daddr_Pr, hostidx_Pr, 
                                   hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                                   portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                                   new_sport_Pr, depth_C, host_C, hidx_Co, 
                                   host_idx, pidx, port_idx, depth_Di, ip_D, 
                                   host_Di, connDomain, cidx, conn_Dis, 
                                   depth_Pri, pkt, conn_Priv, hostMarker, 
                                   daddr, hostidx, hidx, otherEntry, i_Pri, 
                                   indicies, portDomain, sourcePort, destPort, 
                                   new_sport, good, depth_E, i_E, j_, ip_E, 
                                   host_E, indecies_, depth, i_Ev, j, ip_Ev, 
                                   host_Ev, indecies, i_C, i, aa >>

PortScan(self) == portscan1(self) \/ portscan2(self) \/ portscan3(self)
                     \/ portscan4(self) \/ portscan5(self)

foo1 == /\ pc["A"] = "foo1"
        /\ PrintT("Test")
        /\ stack' = [stack EXCEPT !["A"] = << [ procedure |->  "CheckModel",
                                                pc        |->  "Done",
                                                i_C       |->  i_C["A"] ] >>
                                            \o stack["A"]]
        /\ i_C' = [i_C EXCEPT !["A"] = defaultInitValue]
        /\ pc' = [pc EXCEPT !["A"] = "checkModelStart"]
        /\ UNCHANGED << A, B, C, D, N, NN, Aa, Bb, Cc, Dd, Ee, Ff, Gg, Hh, Ii, 
                        Jj, Kk, Ll, Mm, Nn, Oo, Pp, Qq, Rr, Ss, Tt, Uu, Vv, Ww, 
                        Xx, Yy, Zz, H1, H2, MaxPorts, EP1, PortMap1, EP2, 
                        PortMap2, TableFull, EvictionReroute, PortScanInv, 
                        MaxTableSize, hosts, FreeHosts, UsedHosts, Ports, 
                        ExtraPorts, ExtraExtraPorts, T, FreeIPs, UsedIPs, 
                        Connections, SendQueue, RcvQueue, MAX, Marker1, 
                        Marker2, CmdConnect, CmdDisconnect, PortSpaceFull, 
                        depth_, host_, hidx_, host_idx_, pidx_, port_idx_, 
                        depth_D, ip_, host_D, connDomain_, cidx_, conn_, 
                        host_Co, ip_C, hidx_C, host_idx_C, pidx_C, port_idx_C, 
                        host_Dis, ip_Di, connDomain_D, cidx_D, conn_D, host, 
                        ip, connDomain_Di, cidx_Di, conn_Di, depth_P, pkt_, 
                        ipkt_, entry_, conn_P, hostMarker_, ip_idx_, ipidx_, 
                        ip_P, host_P, pkt_P, ipkt_P, entry_P, conn_Pu, 
                        hostMarker_P, ip_idx_P, ipidx_P, ip_Pu, host_Pu, conn, 
                        sport, dstAddr, dport, pkt_Pr, hostMarker_Pr, daddr_, 
                        hostidx_, hidx_P, otherEntry_, i_, indicies_, 
                        portDomain_, sourcePort_, destPort_, new_sport_, 
                        depth_Pr, pkt_Pri, conn_Pr, hostMarker_Pri, daddr_P, 
                        hostidx_P, hidx_Pr, otherEntry_P, i_P, indicies_P, 
                        portDomain_P, sourcePort_P, destPort_P, new_sport_P, 
                        pkt_Priv, conn_Pri, hostMarker_Priv, daddr_Pr, 
                        hostidx_Pr, hidx_Pri, otherEntry_Pr, i_Pr, indicies_Pr, 
                        portDomain_Pr, sourcePort_Pr, destPort_Pr, 
                        new_sport_Pr, depth_C, host_C, hidx_Co, host_idx, pidx, 
                        port_idx, depth_Di, ip_D, host_Di, connDomain, cidx, 
                        conn_Dis, depth_Pu, pkt_Pu, ipkt, entry, conn_Pub, 
                        hostMarker_Pu, ip_idx, ipidx, ip_Pub, host_Pub, 
                        depth_Pri, pkt, conn_Priv, hostMarker, daddr, hostidx, 
                        hidx, otherEntry, i_Pri, indicies, portDomain, 
                        sourcePort, destPort, new_sport, good, depth_E, i_E, 
                        j_, ip_E, host_E, indecies_, depth, i_Ev, j, ip_Ev, 
                        host_Ev, indecies, i, aa >>

Foo == foo1

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == Foo
           \/ (\E self \in ProcSet:  \/ ConnectVuln(self) \/ DisconnectVuln(self)
                                     \/ ConnectMan(self) \/ DisconnectMan(self)
                                     \/ DisconnectVulnMan(self) \/ Evict(self)
                                     \/ PubToPrivVuln(self) \/ PubToPrivMan(self)
                                     \/ PrivToPubMan2(self) \/ PrivToPubVuln(self)
                                     \/ PrivToPubMan(self) \/ Connect(self)
                                     \/ Disconnect(self) \/ PubToPriv(self)
                                     \/ PrivToPub(self) \/ OldPortScan(self)
                                     \/ EventSequenceVuln(self)
                                     \/ EventSequence(self) \/ CheckModel(self)
                                     \/ CheckModelVuln(self) \/ PortScan(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 

=============================================================================
\* Modification History
\* Created Mon Feb 06 22:08:35 UTC 2023 by ben
