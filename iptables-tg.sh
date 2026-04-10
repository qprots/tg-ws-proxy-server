#!/usr/bin/env bash
#
# Telegram TCP traffic redirection to redsocks -> tg-ws-proxy
#
# Usage:
#   sudo ./iptables-tg.sh start   - enable redirection
#   sudo ./iptables-tg.sh stop    - disable redirection
#   sudo ./iptables-tg.sh status  - show rules
#

set -euo pipefail

REDSOCKS_PORT=12345
CHAIN_NAME="TG_WS_REDIRECT"
PROG_DIR="/opt/tg-ws-proxy"

# Telegram IP ranges
SUBNETS=(
    "91.108.56.0/22"
    "91.108.4.0/22"
    "91.108.8.0/22"
    "91.108.16.0/22"
    "91.108.12.0/22"
    "149.154.160.0/20"
    "91.105.192.0/23"
    "91.108.20.0/22"
    "185.76.151.0/24"
)

start() {
    iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true

    # Exclude traffic from proxy user (UID 999) to prevent infinite loop
    iptables -t nat -A "$CHAIN_NAME" -m owner --uid-owner 999 -j RETURN

    for subnet in "${SUBNETS[@]}"; do
        if ! iptables -t nat -C "$CHAIN_NAME" -d "$subnet" -p tcp -j REDIRECT --to-ports "$REDSOCKS_PORT" 2>/dev/null; then
            iptables -t nat -A "$CHAIN_NAME" -d "$subnet" -p tcp -j REDIRECT --to-ports "$REDSOCKS_PORT"
            echo "  + $subnet -> :$REDSOCKS_PORT"
        fi
    done

    if ! iptables -t nat -C OUTPUT -p tcp -j "$CHAIN_NAME" 2>/dev/null; then
        iptables -t nat -A OUTPUT -p tcp -j "$CHAIN_NAME"
        echo "  Chain $CHAIN_NAME linked to OUTPUT"
    fi

    echo ""
    echo "Redirection enabled."
    echo "Telegram traffic -> :$REDSOCKS_PORT -> SOCKS5 :10080 -> WSS"
}

stop() {
    iptables -t nat -D OUTPUT -p tcp -j "$CHAIN_NAME" 2>/dev/null || true
    iptables -t nat -F "$CHAIN_NAME" 2>/dev/null || true
    iptables -t nat -X "$CHAIN_NAME" 2>/dev/null || true

    echo "Redirection disabled."
}

status() {
    echo "=== nat OUTPUT ==="
    iptables -t nat -L OUTPUT -n --line-numbers 2>/dev/null || true
    echo ""
    echo "=== $CHAIN_NAME ==="
    iptables -t nat -L "$CHAIN_NAME" -n --line-numbers 2>/dev/null || echo "(chain does not exist)"
}

case "${1:-}" in
    start)  start  ;;
    stop)   stop   ;;
    status) status ;;
    *)
        echo "Usage: sudo $0 {start|stop|status}"
        exit 1
        ;;
esac
