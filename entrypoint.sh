#!/bin/sh
# picoweb owns :443 directly via kernel TCP sockets + inline TLS 1.3.
# (AF_XDP / AF_PACKET were optimisations that were incompatible with
# AKS pod networking; they're preserved in the source tree but no
# longer used. See .github/copilot-instructions.md.)
echo "entrypoint: starting picoweb on :443 (inline TLS 1.3, kernel sockets)"

exec ./picoweb --tls \
  --tls-cert=/certs/tls.crt --tls-key=/certs/tls.key \
  --picowal-device=/tmp/picowal.wal \
  --picowal-prefix=/wal/ \
  --picowal-bytes=10485760 \
  443 wwwroot 1 100 0 128
