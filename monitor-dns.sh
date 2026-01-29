#! /bin/bash
# Monitor DNS resolution for a specific domain to see when change propogates
# first parameter is domain name
# need to check the domain against a list of DNS servers?
DNS_SERVERS_V4=("8.8.8.8" "1.1.1.1" "208.67.222.222")
DNS_SERVERS_V6=("2001:4860:4860::8888" "2606:4700:4700::1111" "2620:0:ccc::2")
DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi
PREV_IPV4=""
PREV_IPV6=""
while true; do
    for DNS in "${DNS_SERVERS_V4[@]}"; do
        DIG_RESULT=$(dig @"$DNS" +short A "$DOMAIN" | tr '\n' ' ')
        if [ -n "$DIG_RESULT" ] && [ "$DIG_RESULT" != "$PREV_IPV4" ]; then
            echo "$(date): IPv4 changed for $DOMAIN on DNS $DNS: $DIG_RESULT"
        fi
    done
    PREV_IPV4="$DIG_RESULT"
    for DNS in "${DNS_SERVERS_V6[@]}"; do
        DIG_RESULT=$(dig @"$DNS" +short AAAA "$DOMAIN" | tr '\n' ' ')
        if [ -n "$DIG_RESULT" ] && [ "$DIG_RESULT" != "$PREV_IPV6" ]; then
            echo "$(date): IPv6 changed for $DOMAIN on DNS $DNS: $DIG_RESULT"
        fi
    done
    PREV_IPV6="$DIG_RESULT"
    sleep 60
done    
