#!/bin/sh

# openwrt Scheduled Tasks
# minute(0-59) hour(0-23) month(1-31)  year(1-12) week(0-6) 
# 0 3 * * * /etc/vpn/server.sh > /tmp/ss-server.log 2>&1

echo "ss-server"
pidfile="/var/run/ss-server.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi
/usr/bin/ss-server -c /etc/vpn/config.json --acl /etc/vpn/local.acl -f $pidfile

echo "ss-local"
pidfile="/var/run/ss-local.pid"
if [ -f "$pidfile" ]; then
        pid=$(/bin/cat $pidfile)
        /bin/kill $pid
fi
/usr/bin/ss-local -c /var/etc/shadowsocks.json -b 192.168.0.1 -l 7777 --fast-open -u -f $pidfile
