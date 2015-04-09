#!/bin/bash

# $EVENT - "up" or "down", up is defined after interface comes up, down
# after disconnect
# $MODE - jvpn mode, "ncui" or "ncsvc"
# $DNS1, $DNS2 - DNS servers, only in ncsvc mode
# $IP - local VPN ip address, only in ncsvc mode
# $GATEWAY - VPN gateway, only in ncsvc mode
# $INTERFACE - tun interface used for jvpn, only in ncui mode

PIDFILE=/tmp/tunnel.pid

## Kill (whether we're ending or starting up)
if [ -f $PIDFILE ] && [ -s $PIDFILE ] && [ -n "$(pgrep -F $PIDFILE)" ]; then
  pkill -F $PIDFILE
fi
echo -n > $PIDFILE ## clean PIDFILE

## Init tunnel only if we're starting up
if [ -n "$EVENT" ] && [ $EVENT = "up" ]; then
  su - jv -c "ssh -N -q user@hostovervpn.domain.private -D 8080 -L1080:127.0.0.1:80 & echo \$!" > $PIDFILE
fi
