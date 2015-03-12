#!/bin/sh
iptables -t nat -D PREROUTING -p tcp -d 10.168.172.192 -j SHADOWDNS >/dev/null 2>&1
iptables -t nat -D OUTPUT -p tcp -d 10.168.172.192 -j SHADOWDNS >/dev/null 2>&1
iptables -t nat -F SHADOWDNS >/dev/null 2>&1
iptables -t nat -X SHADOWDNS >/dev/null 2>&1

iptables -t nat -N SHADOWDNS
iptables -t nat -A SHADOWDNS -p tcp -j REDIRECT --to-ports 1050
iptables -t nat -A PREROUTING -p tcp -d 10.168.172.192 -j SHADOWDNS
iptables -t nat -A OUTPUT -p tcp -d 10.168.172.192 -j SHADOWDNS

/etc/init.d/shadowsocks restart
