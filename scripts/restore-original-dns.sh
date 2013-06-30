#!/bin/sh

# This script will restore the DNS server settings to the original DNS settings
# discarding the DNS servers proposed by the VPN client.
# This can be useful in cases where the DNS servers proposed by the VPN client
# are not accessible over the VPN connection.

if [ "${EVENT}" = "up" ]
then
    if [ -f /etc/jnpr-nc-resolv.conf ]
    then
        printf "\nUse original DNS servers instead of those provided by the VPN client.\n"

        # Copy original DNS settings back.
        cp /etc/jnpr-nc-resolv.conf /etc/resolv.conf

        printf "  DNS servers proposed by the VPN client:\n    DNS1: ${DNS1}\n    DNS2: ${DNS2}\n"

        printf "  Original DNS servers:\n"
        awk -F ' ' '{ if ($1 == "nameserver") { nbr_DNS_servers += 1 ; print "    DNS" nbr_DNS_servers ": " $2 } } END { printf "\n" }' /etc/resolv.conf
    fi
fi
