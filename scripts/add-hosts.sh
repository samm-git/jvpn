#!/bin/sh

# This script will add hosts to /etc/hosts so those servers can be reached
# by their hostname instead of only by their ip address, so you are not
# restricted to hostnames known by the DNS server(s) provided by the VPN
# client.



# Add here your "IP - hostname" pairs that you want to add to /etc/hosts.
ADD_HOSTS='
# BEGIN hosts added by add-hosts.sh (jvpn)

111.111.111.111	server1
123.123.123.123	server2

# END hosts added by add-hosts.sh (jvpn)
'



if [ "${EVENT}" = "up" ]
then
    if [ -f /etc/hosts ]
    then
        printf "\nAdd hosts to /etc/hosts.\n"

        # Add hosts at the end of the file.
        printf '%s' "${ADD_HOSTS}" >> /etc/hosts
    fi
fi
