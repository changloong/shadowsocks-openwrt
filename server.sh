#!/bin/sh
echo "ss-server"
pidfile="/var/run/ss-server.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi
/usr/bin/ss-server -c /etc/vpn/config.json --acl /etc/vpn/local.acl -f $pidfile

#echo "ss-dns-redir"
pidfile="/var/run/ss-dns-redir.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi
#/usr/bin/ss-redir -c /etc/vpn/dns.json -b 0.0.0.0 -f $pidfile

#echo "ss-dns-tunnel"
pidfile="/var/run/ss-dns-tunnel.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi
#/usr/bin/ss-tunnel -c /etc/vpn/dns.json -l 5353 -L 10.168.172.192:53 -f $pidfile -u

echo "ss-local"
pidfile="/var/run/ss-local.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi
/usr/bin/ss-local -c /var/etc/shadowsocks.json -b 192.168.0.1 -l 7777 --fast-open -u -f $pidfile
