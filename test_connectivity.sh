#!/usr/bin/env bash
#
# TG WS Proxy - Connectivity Test Script
# Usage: ./test_connectivity.sh <hostname>
#

set -euo pipefail

TARGET_HOST="${1:-}"

if [[ -z "$TARGET_HOST" ]]; then
    echo "Usage: $0 <hostname>"
    exit 1
fi

echo "🔍 Testing $TARGET_HOST..."

ssh "$TARGET_HOST" "bash -s" << 'EOF'
set -euo pipefail

echo "--- 1. Docker Containers ---"
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "Names|tg-ws"

echo -e "\n--- 2. Listening Ports ---"
sudo ss -tlnp | grep -E "10080|12345" || echo "❌ No ports found!"

echo -e "\n--- 3. iptables Rules (TG_WS_REDIRECT) ---"
if sudo iptables -t nat -L TG_WS_REDIRECT -v -n >/dev/null 2>&1; then
    sudo iptables -t nat -L TG_WS_REDIRECT -v -n | head -n 5
    echo "... (total rules check)"
else
    echo "❌ iptables chain missing!"
fi

echo -e "\n--- 4. Active Redirection Check ---"
# Clear counters to see fresh hit
sudo iptables -t nat -Z TG_WS_REDIRECT
echo "Performing test connection to 149.154.167.51..."
timeout 2 bash -c "cat < /dev/null > /dev/tcp/149.154.167.51/443" 2>/dev/null || true

HITS=$(sudo iptables -t nat -L TG_WS_REDIRECT -v -n | grep "149.154.160.0/20" | awk '{print $1}')
if [ "$HITS" != "0" ]; then
    echo "✅ Success! Traffic redirected ($HITS packets captured)"
else
    echo "❌ Failure! Traffic NOT redirected"
fi

echo -e "\n--- 5. Proxy Logs (last 5 lines) ---"
sudo docker logs tg-ws-proxy 2>&1 | tail -n 5
EOF
