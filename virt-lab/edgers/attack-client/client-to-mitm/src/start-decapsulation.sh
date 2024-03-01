#!/bin/bash
#!/bin/bash

# Check if tun0 interface exists
if ! ip addr show tun0 &> /dev/null; then
    echo "Error: tun0 interface not found."
    exit 1
fi

# Extract IP address of tun0 interface
ip_address=$(ip addr show tun0 | grep -oP 'inet \K[\d.]+')

if [ -z "$ip_address" ]; then
    echo "Error: Unable to extract IP address of tun0 interface."
    exit 1
fi



# sike wrong number of args ---> (public_iface, attacker_pub_ip, victim_ip, vpn_ip, vpn_port, https_port, webdnsserver_ip)
sudo /vagrant/client-to-mitm/src/decapsulation enp0s8 192.168.254.254 192.168.1.254 192.168.2.254 1194 80 192.168.3.254 $ip_address
