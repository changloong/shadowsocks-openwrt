#!/bin/sh
pidfile="/var/run/ss-server.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi
#echo "ss-server"
/usr/bin/ss-server -c /etc/vpn/config.json --acl /etc/vpn/local.acl -f $pidfile

pidfile="/var/run/ss-dns.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi

#echo "ss-redir"
/usr/bin/ss-redir -c /etc/vpn/dns.json -b 0.0.0.0 -f $pidfile

pidfile="/var/run/ss-local.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi

#echo "ss-local"
/usr/bin/ss-local -c /var/etc/shadowsocks.json -b 192.168.0.1 -l 7777 --fast-open -u -f $pidfile
