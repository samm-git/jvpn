#!/bin/sh

# this is sample script for the jvpn. It could be used from jvpn if script variable 
# is defined. jvpn defines some variables which can be used inside:
#
# $EVENT - "up" or "down", up is defined after interface comes up, down
# after disconnect
# $MODE - jvpn mode, "ncui" or "ncsvc"
# $DNS1, $DNS2 - DNS servers, only in ncsvc mode
# $IP - local VPN ip address, only in ncsvc mode
# $GATEWAY - VPN gateway, only in ncsvc mode
# $INTERFACE - tun interface used for jvpn, only in ncui mode
echo "EVENT: $EVENT, MODE: $MODE, DNS1: $DNS1, DNS2: $DNS2, IP: $IP"
echo "GATEWAY: $GATEWAY, INTERFACE: $INTERFACE"

# sample route table modification for the www.whatismyipaddress.com
if [ $EVENT = "up" -a $MODE = "ncsvc" ]
then
    route add 67.203.139.148 gw $GATEWAY
    route add 66.80.82.69 gw $GATEWAY
fi
