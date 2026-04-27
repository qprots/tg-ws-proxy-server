#!/usr/bin/env bash
#
# TG WS Proxy - One-click Deploy Script
# Usage: ./deploy.sh <hostname>
# Example: ./deploy.sh server
#

set -euo pipefail

TARGET_HOST="${1:-}"

if [[ -z "$TARGET_HOST" ]]; then
    echo "Usage: $0 <hostname>"
    exit 1
fi

REMOTE_DIR="/opt/tg-ws-proxy"
TMP_DIR="/tmp/tg-ws-proxy-deploy"

echo "🚀 Starting deployment to $TARGET_HOST..."

# 1. Sync files
echo "📦 Syncing files..."
rsync -avz --exclude '.git' --exclude '__pycache__' --exclude '*.pyc' \
    ./ "$TARGET_HOST:$TMP_DIR/"

# 2. Remote setup
echo "🛠  Configuring remote server..."
ssh "$TARGET_HOST" "bash -s" << EOF
set -euo pipefail
sudo mkdir -p "$REMOTE_DIR"
sudo rsync -a "$TMP_DIR/" "$REMOTE_DIR/"
sudo rm -rf "$TMP_DIR"

cd "$REMOTE_DIR"

# Setup systemd service
echo 'Configuring systemd service...'
sudo cp tg-ws-proxy-iptables.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable tg-ws-proxy-iptables

# Start containers
echo 'Launching containers...'
# Check for docker compose v2 then v1
if docker compose version >/dev/null 2>&1; then
    sudo docker compose up -d --build
else
    sudo docker-compose up -d --build
fi

# Enable iptables redirection
echo 'Applying iptables rules...'
sudo bash iptables-tg.sh start
sudo systemctl start tg-ws-proxy-iptables

# Setup daily restart cron (2:00 AM server time)
echo 'Configuring daily restart cron...'
CRON_CMD="0 2 * * * cd $REMOTE_DIR && docker compose restart tg-ws-redsocks tg-ws-proxy 2>/dev/null || docker-compose restart tg-ws-redsocks tg-ws-proxy"
(sudo crontab -l 2>/dev/null | grep -v 'tg-ws-proxy' || true; echo "\$CRON_CMD") | sudo crontab -
echo 'Cron set: daily restart at 02:00'
EOF

echo "✅ Deployment to $TARGET_HOST complete!"
echo "📈 Run ./test_connectivity.sh $TARGET_HOST to verify."
