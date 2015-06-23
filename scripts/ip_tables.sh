#!/bin/bash
ADDR="172.25.1.0/24"

iptables -A FORWARD -o eth0 -i vboxnet0 -s $ADDR -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE

sysctl -w net.ipv4.ip_forward=1
