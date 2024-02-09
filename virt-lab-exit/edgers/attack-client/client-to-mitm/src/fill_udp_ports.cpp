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
#define PORT_RANGE_START 32700 
#define PORT_RANGE_END 62000
#define DNS_IP "192.168.3.2" 
#define VPN_IP "192.168.2.2" 
#define DNS_PORT 53

	PacketSender sender;
	NetworkInterface iface(iface);

	IP pkt = IP(DNS_IP) / UDP(DNS_PORT, PORT_RANGE_START);
	IP& ip = pkt.rfind_pdu<IP>();
	ip.ttl(2);
	UDP& udp = pkt.rfind_pdu<UDP>();
	
	IP pkt_resp = IP(VPN_IP) / UDP(PORT_RANGE_START, DNS_PORT);
	IP& ip_resp = pkt_resp.rfind_pdu<IP>();
	ip.ttl(2);
	UDP& udp_resp = pkt_resp.rfind_pdu<UDP>();
	
	while (true) {
		for (unsigned short sport = PORT_RANGE_START;
				sport < PORT_RANGE_END; sport++) {
			udp.sport(sport);
			udp_resp.dport(sport);
			sender.send(pkt, iface);
			usleep(10);
			sender.send(pkt_resp, iface);
jjkj		}
		usleep(10000000);
	}
}

int main(int argc, char** argv) {
	if (argc != 2) {
		cout << "sike wrong number of args ---> (iface)\n";
		return 0;
	}
	iface = argv[1];
        thread udp_ephemeral_scan_thread(
			udp_fill_ephemeral_port_range);
	udp_ephemeral_scan_thread.join();


	return 0;

