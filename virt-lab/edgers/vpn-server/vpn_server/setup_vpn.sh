#!/bin/bash
#

export EASYRSA_BATCH=1

BORDER=">>>>>>>>>>>>>>"
printf "$BORDER Installing openvpn and EasyRSA $BORDER \n\n"

sudo apt-get update -y
sudo apt-get install openvpn -y

wget -P ~/ https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz

cd ~
tar xvf EasyRSA-3.0.8.tgz

printf "$BORDER Setting default openvpn vars $BORDER \n\n"

echo `pwd`
cd ~/EasyRSA-3.0.8/
cp vars.example vars

sed -i "s/#set_var EASYRSA_REQ_COUNTRY    \"US\"/set_var EASYRSA_REQ_COUNTRY    \"US\"/g " vars
sed -i "s/#set_var EASYRSA_REQ_PROVINCE   \"California\"/set_var EASYRSA_REQ_PROVINCE   \"New Mexico\"/g" vars
sed -i "s/#set_var EASYRSA_REQ_CITY       \"San Francisco\"/set_var EASYRSA_REQ_CITY       \"Albuquerque\"/g" vars
sed -i "s/#set_var EASYRSA_REQ_ORG        \"Copyleft Certificate Co\"/set_var EASYRSA_REQ_ORG        \"Copyleft Certificate Co\"/g" vars
sed -i "s/#set_var EASYRSA_REQ_EMAIL      \"me@example.net\"/set_var EASYRSA_REQ_EMAIL      \"me@example.net\"/g" vars
sed -i "s/#set_var EASYRSA_REQ_OU         \"My Organizational Unit\"/set_var EASYRSA_REQ_OU         \"Breakpointingbad\"/g" vars



printf "$BORDER Building the certificate authority $BORDER \n\n"

./easyrsa init-pki

./easyrsa build-ca nopass



printf "$BORDER Creating the server certificate $BORDER \n\n"

./easyrsa gen-req server nopass

sudo cp ~/EasyRSA-3.0.8/pki/private/server.key /etc/openvpn/

./easyrsa sign-req server server

sudo cp ~/EasyRSA-3.0.8/pki/ca.crt /etc/openvpn/
sudo cp ~/EasyRSA-3.0.8/pki/issued/server.crt /etc/openvpn/

printf "$BORDER Generating Diffie-Hellman keys to use during key exchange $BORDER \n\n"

./easyrsa gen-dh

printf "$BORDER Generating HMAC signature to strengthen the server’s TLS integrity verification"

openvpn --genkey --secret ta.key

sudo cp ~/EasyRSA-3.0.8/ta.key /etc/openvpn/
sudo cp ~/EasyRSA-3.0.8/pki/dh.pem /etc/openvpn/

printf "$BORDER Generating client certificate and key pair $BORDER \n\n"

mkdir -p ~/client-configs/keys

chmod -R 700 ~/client-configs
./easyrsa gen-req client1 nopass
./easyrsa gen-req client2 nopass

./easyrsa sign-req client client1
./easyrsa sign-req client client2

cp ~/EasyRSA-3.0.8/pki/issued/client1.crt ~/client-configs/keys/
cp ~/EasyRSA-3.0.8/pki/issued/client2.crt ~/client-configs/keys/


printf "$BORDER Configuring the openvpn service using generated keys + certs $BORDER \n\n"

sudo cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz /etc/openvpn/
sudo gzip -d /etc/openvpn/server.conf.gz


sudo sed -i "s/;tls-auth ta.key 0/tls-auth ta.key 0/g"  /etc/openvpn/server.conf
sudo sed -i "s/;cipher AES-128-CBC/cipher AES-128-CBC/g"  /etc/openvpn/server.conf

sudo sed -i "s/;user nobody/user nobody/g"  /etc/openvpn/server.conf

# TODO: Fix the client key generation scripts so that this doesn't need to be turned on
sudo sed -i "s/;duplicate-cn/duplicate-cn/g"  /etc/openvpn/server.conf

#sudo sed -i "s/;push \"redirect-gateway def1 bypass-dhcp\"/push \"redirect-gateway def1 bypass-dhcp\"/g"  /etc/openvpn/server.conf
#sudo sed -i "s/;push \"dhcp-option DNS 208.67.222.222\"/push \"dhcp-option DNS 208.67.222.222\"/g"  /etc/openvpn/server.conf
#sudo sed -i "s/;push \"dhcp-option DNS 208.67.220.220\"/push \"dhcp-option DNS 208.67.220.220\"/g"  /etc/openvpn/server.conf
# sudo sed -i 's/;local a\.b\.c\.d/local 192.168.2.254\nlocal fd12:2345:6789:2::fe/g' /etc/openvpn/server.conf
sudo sed -i 's/;local a\.b\.c\.d/local 192.168.2.254/g' 


sudo sed -i "s/dh dh2048.pem/dh dh.pem/g"  /etc/openvpn/server.conf

sudo bash -c 'cat >> /etc/openvpn/server.conf << EOF

auth SHA256
EOF'

## Changes these later once after testing the base c2mitm attack
# sudo sed -i "s/port 1194/port 443/g"  /etc/openvpn/server.conf
# sudo sed -i "s/proto udp/proto tcp/g"  /etc/openvpn/server.conf

printf "$BORDER Adjusting the servers network config to allow for vpn things $BORDER \n\n"

sudo sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g"  /etc/sysctl.conf
sudo sysctl -p


sudo bash -c 'cat >> /etc/ufw/before.rules << EOF
# START OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from OpenVPN client to enp0s8
-A POSTROUTING -s 10.8.0.0/8 -o enp0s8 -j MASQUERADE
COMMIT
# END OPENVPN RULES
EOF'


sudo sed -i "s/DEFAULT_FORWARD_POLICY=\"DROP\"/DEFAULT_FORWARD_POLICY=\"ACCEPT\"/g" /etc/default/ufw
# sudo ufw allow 443/tcp
sudo ufw allow 1194/udp
sudo ufw allow OpenSSH

sudo ufw disable
sudo ufw --force enable

printf "$BORDER Enabling the openvpn service $BORDER \n\n"



sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server



BORDER=">>>>>>>>>>>>>>>>"

printf "$BORDER Setting up base client config file\n\n"

mkdir -p ~/client-configs/files
chmod 700 ~/client-configs/files


cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf ~/client-configs/base.conf


sed -i "s/my-server-1 1194/192.168.2.254 1194/g" ~/client-configs/base.conf
# sed -i "s/proto udp/proto tcp/g" ~/client-configs/base.conf

sed -i "s/;user nobody/user nobody/g" ~/client-configs/base.conf
sed -i "s/;group nobody/group nobody/g" ~/client-configs/base.conf

sed -i "s/ca ca.crt/# ca ca.crt/g" ~/client-configs/base.conf
sed -i "s/cert client.crt/# cert client.crt/g" ~/client-configs/base.conf
sed -i "s/key client.key/# key client.key/g" ~/client-configs/base.conf


cat >> ~/client-configs/base.conf << EOF
cipher AES-128-CBC
auth SHA256
key-direction 1
# script-security 2
# up /etc/openvpn/update-resolv-conf
# down /etc/openvpn/update-resolv-conf
EOF

cp ~/EasyRSA-3.0.8/pki/ca.crt ~/client-configs/keys/
cp ~/EasyRSA-3.0.8/pki/private/client1.key ~/client-configs/keys/
cp ~/EasyRSA-3.0.8/pki/private/client2.key ~/client-configs/keys/
cp ~/EasyRSA-3.0.8/ta.key ~/client-configs/keys/

printf "$BORDER Creating make client config script..\n\n"

touch ~/client-configs/make_config.sh

cat >> ~/client-configs/make_config.sh << EOF

# First argument: Client identifier

KEY_DIR=~/client-configs/keys
OUTPUT_DIR=~/client-configs/files
BASE_CONFIG=~/client-configs/base.conf

cat \${BASE_CONFIG} <(echo -e '<ca>') \${KEY_DIR}/ca.crt <(echo -e '</ca>\n<cert>') \${KEY_DIR}/\${1}.crt <(echo -e '</cert>\n<key>') \${KEY_DIR}/\${1}.key <(echo -e '</key>\n<tls-auth>') \${KEY_DIR}/ta.key <(echo -e '</tls-auth>') > \${OUTPUT_DIR}/\${1}.ovpn
EOF

chmod 700 ~/client-configs/make_config.sh


printf "$BORDER Making client config file for client1\n\n"

cd ~/client-configs
./make_config.sh client1
./make_config.sh client2

sed -i "s/Subject: CN=ChangeMe/Subject: CN=client1/g" ~/client-configs/files/client1.ovpn
sed -i "s/Subject: CN=ChangeMe/Subject: CN=client2/g" ~/client-configs/files/client2.ovpn

# Copy the VPN files to the shared folder on the host
sudo cp ~/client-configs/files/client* /vagrant
ls ~/client-configs/files

