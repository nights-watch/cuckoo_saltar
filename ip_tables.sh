#!/bin/bash

iptables -A FORWARD -o eth0 -i vboxnet0 -s $1 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE

sysctl -w net.ipv4.ip_forward=1
