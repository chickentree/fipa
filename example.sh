#!/bin/sh

# api_key: https://dash.cloudflare.com/profile/api-tokens
# zone_identifier: https://dash.cloudflare.com/
# identifier: https://api.cloudflare.com/#dns-records-for-a-zone-list-dns-records

fipa -d 1 -i ppp0 -v 4 | mawk -W interactive '{if ($1) print $1}' | while read a
do
  curl -X PUT 'https://api.cloudflare.com/client/v4/zones/:zone_identifier/dns_records/:identifier' \
  -H 'Authorization: Bearer :api_key' \
  -H 'Content-Type: application/json' \
  --data '{"type":"A","name":"example","content":"'$a'","proxied":false}'
done
