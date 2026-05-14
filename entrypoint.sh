#!/bin/sh
# Detect the primary NIC (default route interface)
IFNAME=$(ip route show default | awk '{print $5; exit}')
IFNAME=${IFNAME:-eth0}
echo "entrypoint: using interface $IFNAME (XDP redirect mode)"

exec ./picoweb --tls --tls-xdp --tls-ifname="$IFNAME" \
  --tls-cert=/certs/tls.crt --tls-key=/certs/tls.key \
  --http-early-hints \
  443 wwwroot 1 100 0 64
