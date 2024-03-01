simple-relay:
	g++ -O3 -o simple-relay simple-relay.cpp -lpthread -ltins -std=c++11
	


simple-relay.dbg:
	g++ -O0 -g -o simple-relay.gdb simple-relay.cpp -lpthread -ltins -std=c++11

full-relay:
	g++ -O3 -o full-relay full-relay.cpp -lpthread -ltins -std=c++11
bind_ipv6:
	g++ -O3 -o bind_ipv6 bind_ipv6.cpp -lpthread -ltins -std=c++11

test-sender-ipv6:
	g++ -O3 -o test-sender-ipv6 test-sender-ipv6.cpp -lpthread -ltins -std=c++11

full-relay-ipv6:
	g++ -O3 -o full-relay-ipv6 full-relay-ipv6.cpp -lpthread -ltins -std=c++11

http-relay:
	g++ -O3 -o http-relay http-relay.cpp -lpthread -ltins -std=c++11

decapsulation:
	g++ -O3 -o decapsulation decapsulation.cpp -lpthread -ltins -std=c++11

decap_relay:
	g++ -O3 -o decap_relay decap_relay.cpp -lpthread -ltins -std=c++11

decap-relay:
	g++ -O3 -o decap-relay decap-relay.cpp -lpthread -ltins -std=c++11

basic-http-server:
	g++ -O3 -o basic-http-server basic-http-server.cpp -lpthread -ltins -std=c++11

fill_udp_ports:
	g++ -O3 -o fill_udp_ports fill_udp_ports.cpp -lpthread -ltins -std=c++11

txid-bruteforce:
	g++ -O3 -o txid-bruteforce txid-bruteforce.cpp -lpthread -ltins -std=c++11


dns-reroute:
	g++ -O3 -o dns-reroute dns-reroute.cpp -lpthread -ltins -std=c++11


clean:
	rm -rf basic-http-server full-relay simple-relay simple-relay.gdb decapsulation *~

cleanfull:
	rm -rf  full-relay decapsulation

