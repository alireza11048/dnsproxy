#!/bin/ash

if [ -z $DNS_PORT ]; then
    DNS_PORT=53
fi

if [ -z $DNS_SERVER ]; then
    DNS_SERVER="8.8.8.8"
fi

if [ -z $DOH_SERVER ]; then
    DOH_SERVER="https://free.shecan.ir/dns-query"
fi

if [ -f "/etc/resolv.conf" ]; then
    rm /etc/resolv.conf
fi
echo "nameserver $DNS_SERVER" > /etc/resolv.conf

./src/dnsproxy -p $DNS_PORT -U $DOH_SERVER