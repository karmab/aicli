#!/bin/bash

IP=%(prefix)s.$((%(num)s + $RANDOM %% 254))
NETMASK=%(netmask)s
nmcli connection modify "Wired connection 1" +ipv4.addresses $IP/$NETMASK ipv4.method auto
nmcli device reapply enp1s0
