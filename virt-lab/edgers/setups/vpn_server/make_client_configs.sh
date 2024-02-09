#!/bin/bash
#

BORDER=">>>>>>>>>>>>>>>>"

printf "$BORDER Setting up base client config file\n\n"

mkdir -p ~/client-configs/files
chmod 700 ~/client-configs/files


cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf ~/client-configs/base.conf


sed -i "s/my-server-1 1194/192.168.2.2 443/g" ~/client-configs/base.conf
sed -i "s/proto udp/proto tcp/g" ~/client-configs/base.conf

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


printf "$BORDER Creating make client config script..\n\n"

touch ~/client-configs/make_config.sh

cat >> ~/client-configs/make_config.sh << EOF
#!/bin/bash

# First argument: Client identifier

KEY_DIR=~/openvpn-ca/keys
OUTPUT_DIR=~/client-configs/files
BASE_CONFIG=~/client-configs/base.conf

cat \${BASE_CONFIG} <(echo -e '<ca>') \${KEY_DIR}/ca.crt <(echo -e '</ca>\n<cert>') \${KEY_DIR}/\${1}.crt <(echo -e '</cert>\n<key>') \${KEY_DIR}/\${1}.key <(echo -e '</key>\n<tls-auth>') \${KEY_DIR}/ta.key <(echo -e '</tls-auth>') > \${OUTPUT_DIR}/\${1}.ovpn
EOF

chmod 700 ~/client-configs/make_config.sh


printf "$BORDER Making client config file for client1\n\n"

cd ~/client-configs
./make_config.sh client1
ls ~/client-configs/files
