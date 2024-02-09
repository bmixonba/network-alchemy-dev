#!/bin/bash
#

echo "Starting dns server container.."

docker run --name bind -d -it --restart=always \
  --publish=192.168.3.2:53:53/tcp --publish=192.168.3.2:53:53/udp --publish 10000:10000/tcp \
  -v /home/vagrant/bind_config/:/data/bind/etc/ \
  sameersbn/bind:9.16.1-20200524

#-v /home/vagrant/copy_config/:/data/bind/etc/ \
#--volume /srv/docker/bind:/data \
#--volume /home/vagrant/named.conf.options:/data/bind/etc/named.conf.options \
