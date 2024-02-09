#/bin/bash
#

NOW=$(date '+%F %T')
printf "\n\nStarting inject attack at $NOW\n"


sudo ./uud_send 192.168.3.2 53 192.168.2.2 32000 62000


NOW=$(date '+%F %T')
printf "\n\nFinished inject attack at $NOW\n"
