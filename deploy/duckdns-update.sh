#!/bin/bash
# Keeps the DuckDNS A record for pleroma-aicds pointed at this VPS.
#
# Token is read from /opt/pleroma/.duckdns-token which contains:
#   DUCKDNS_TOKEN=your-token-here
# Keep that file mode 600, owned by root or opt — NEVER commit it.
#
# Install:
#   sudo crontab -e
#   # add:
#   */5 * * * * /opt/pleroma/deploy/duckdns-update.sh >> /var/log/duckdns.log 2>&1

set -u

TOKEN_FILE="/opt/pleroma/.duckdns-token"
SUBDOMAIN="pleroma-aicds"

if [ ! -r "$TOKEN_FILE" ]; then
    echo "$(date -Is) duckdns token file missing: $TOKEN_FILE"
    exit 1
fi

# shellcheck source=/dev/null
. "$TOKEN_FILE"

if [ -z "${DUCKDNS_TOKEN:-}" ]; then
    echo "$(date -Is) DUCKDNS_TOKEN not set"
    exit 1
fi

response=$(curl -s "https://www.duckdns.org/update?domains=${SUBDOMAIN}&token=${DUCKDNS_TOKEN}&ip=")

if [ "$response" = "OK" ]; then
    echo "$(date -Is) duckdns update OK"
else
    echo "$(date -Is) duckdns update FAILED: $response"
    exit 1
fi
