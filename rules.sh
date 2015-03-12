#!/bin/sh

EXT_ARGS=""

usage() {
        cat <<-EOF
                Usage: ss-rules [options]

                Valid options are:

                    -s <server_host>        hostname or ip of shadowsocks remote server
                    -l <local_port>         port number of shadowsocks local server
                    -c <config_file>        config file of shadowsocks
                    -i <ignore_list_file>   config file of ignore list
					-a <lan_ips>            lan ip of access control, need a prefix to
							                       define access control mode
                    -e <extra_options>      extra options of iptables
                    -f                      flush the rules
EOF
}

get_ip() {
        local COUNT=0
        local NS=114.114.114.114
        until ping -c1 $NS>/dev/null 2>&1; do
                if [ "$COUNT" = 6 ]; then
                        echo "Operation timeout."
                        exit 1
                fi
                COUNT=$(($COUNT + 1))
        done
        nslookup $1 $NS | grep -v "$NS" | \
        awk '{ip[NR]=$3}\
                END{for(i=NR;i>0;i--)\
                        {if(ip[i] ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/)\
                                {print ip[i];break;}}}'
}

flush_r() {
        local IPT
        while true; do
                IPT=$(iptables-save | grep "^-A PREROUTING")
                if [ -z "$IPT" ]; then
                        sleep 1
                        continue
                fi
                eval $(echo "$IPT" | grep "shadowsocks" | \
                        sed 's#^-A#-D#g' | awk '{printf("iptables -t nat %s;\n",$0)}')
                if echo "$IPT" | grep -q "SHADOWSOCKS"; then
                        iptables -t nat -D PREROUTING -p tcp -s 192.168.0.0/16 -j SHADOWSOCKS
                        iptables -t nat -F SHADOWSOCKS>/dev/null 2>&1 && \
                        iptables -t nat -X SHADOWSOCKS
                fi
                break
        done
}

iptab_r() {                                                                                                                                                        
        local PASS=$(echo -e "$IPPASS" | awk '$1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}/ {printf("-A SHADOWSOCKS -p tcp -d %s -j RETURN\n", $1)}')
        local BODY=$(echo -e "$IPLIST" | awk '$1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}/ {printf("-A SHADOWSOCKS -p tcp -d %s -j REDIRECT --to-ports LOCAL_PORT\n", $1)}')
        BODY=$(echo -e "$BODY" | sed -e "s/LOCAL_PORT/$LOCAL_PORT/g")
        BODY="*nat                                                   
:SHADOWSOCKS - [0:0]                                                 
$PASS                         
$BODY        
-A SHADOWSOCKS -p tcp -d 0.0.0.0/0 -j RETURN                         
-A PREROUTING -p tcp -s 192.168.0.0/16 -j SHADOWSOCKS                                  
COMMIT"                        
        echo -e "$BODY" | iptables-restore -n                        
        exit $?                                                      
}                                                                    
                                                                     
while getopts ":s:l:c:i:e:a:of" arg; do                               
        case $arg in                                                 
                s)                                                   
                        SERVER=$OPTARG                               
                        ;;                                           
                l)                                                   
                        LOCAL_PORT=$OPTARG                           
                        ;;                                           
                c)                                                   
                        CONFIG=$OPTARG                               
                        ;;                                           
                i)                                                   
                        IGNORE=$OPTARG                               
                        ;;                                           
                e)                                                   
                        EXT_ARGS="$EXT_ARGS $OPTARG"                 
                        ;;
				a)
						LAN_AC_IP=$OPTARG
						;; 
				o)
						OUTPUT=1
						;;                                        
                f)                                                   
                        flush_r                                      
                        exit 0                                       
                        ;;                                           
        esac                                                                          
done

if [ -f "$CONFIG" ]; then                                            
        eval $(awk -F'[,:]' '{                                       
                for (i=1; i<=NF; i++) {                              
                        if ($i ~ /"server"/)                         
                                {printf("server=%s;", $(i+1))}       
                        if ($i ~ /"local_port"/)                     
                                {printf("local_port=%s;", $(i+1))}   
                        if ($i ~ /"local_address"/)                  
                                {printf("local_address=%s;", $(i+1))}
                }                                                    
        }' $CONFIG | tr -d '" ')                                     
fi                                                                   
                                                                     
: ${SERVER:=$server}                                                 
: ${LOCAL_PORT:=$local_port}                                         
: ${LOPAL_ADDR:=$local_address}                                      
                                                                     
if [ -z "$LOPAL_ADDR" ]; then                                        
        LOPAL_ADDR="127.0.0.1"                                       
fi                                                                   
                                                                     
if [ -z "$SERVER" ] || [ -z "$LOCAL_PORT" ]; then                                     
        usage                                                        
        exit 2                                                             
fi                                                                        
                                                                     
if !(echo "$SERVER" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"); then
        echo "The $SERVER is not ip, trying to resolve it."          
        SERVER=$(get_ip $SERVER)                                     
        [ -z "$SERVER" ] && exit 1                                   
        echo "Server IP: $SERVER."                                   
fi                                                                   

#LOCAL_IP=$(uci get network.lan.ipaddr 2>/dev/null)
IPLIST="8.8.4.0/24\n8.8.8.0/24"
          
if [ -f "$IGNORE" ]; then
        IPLIST="$(sed '/^;/d' $IGNORE)"  
        IPPASS=$(echo -e "$IPLIST" |sed '/^[^#]/d')
        IPPASS=$(echo -e "$IPPASS" |sed 's/#//g')
        IPLIST="$(echo -e "$IPLIST" |sed '/^#/d')"
fi
IPPASS="$SERVER\n$IPPASS"
IPPASS=$(echo -e "$IPPASS" |sed '/^\s*$/d')
IPLIST=$(echo -e "$IPLIST" |sed '/^\s*$/d')
                     
flush_r                                                              
iptab_r                                                              
                                                              
exit $?

