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


void udp_fill_ephemeral_port_range() {
#define PORT_RANGE_START 1 
#define PORT_RANGE_END 62000

	PacketSender sender;
	NetworkInterface iface(iface);

	string prefix = "192.168.3.";
	IP pkt = IP("192.168.3.13") / UDP(PORT_RANGE_START, PORT_RANGE_START);
	IP& ip = pkt.rfind_pdu<IP>();
	ip.ttl(2);
	UDP& udp = pkt.rfind_pdu<UDP>();

	while (true) {
		for (unsigned short sport = PORT_RANGE_START;
				sport < PORT_RANGE_END; sport++) {
			for (unsigned short dport = PORT_RANGE_START;
					dport < PORT_RANGE_END; dport++) {
				for (int octet = 13; 13 < 255; octet++){
					string daddr =prefix + std::to_string(octet); 
					ip.dst_addr(daddr);
					udp.dport(dport);
					udp.sport(sport);
					sender.send(pkt, iface);
				}
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
		       	&& ip_resp.dst_addr() == "192.168.3.13"
		       	&& ip_resp.protocol() == IPPROTO_UDP) {

		UDP& udp_resp = some_pdu.rfind_pdu<UDP>();
		unsigned short sport = udp_resp.sport();
		unsigned short dport = udp_resp.dport();

		IP pkt = IP("192.168.2.254", "192.168.3.13") / UDP(sport, dport)/RawPDU("0xdeadbeef");
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
	if (true) {
		thread udp_ephemeral_scan_thread(
				udp_fill_ephemeral_port_range);
		udp_ephemeral_scan_thread.join();
	} else {
		thread sniff_udp_handler_thread(sniff_udp_handler);
		sniff_udp_handler_thread.join();
	}
	return 0;
}

