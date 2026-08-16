#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/db
    chown -R paste:paste /app/db
    exec su-exec paste "$0" "$@"
fi

# Cloudflared tunnel support
TUNNEL_NAME="${TUNNEL_NAME:-}"
CF_DIR="${CLOUDFLARED_DIR:-/home/paste/.cloudflared}"
TRUST_PROXY=0

if [ -n "$TUNNEL_NAME" ]; then
    if [ -f "$CF_DIR/config.yml" ]; then
        cloudflared tunnel --config "$CF_DIR/config.yml" run "$TUNNEL_NAME" &

        echo "Waiting for Cloudflared tunnel to connect..."
        for i in $(seq 1 30); do
            if cloudflared tunnel info "$TUNNEL_NAME" > /dev/null 2>&1; then
                echo "Tunnel connected!"
                break
            fi
            sleep 2
        done
        TRUST_PROXY=1
    else
        echo "Cloudflare tunnel configuration not found at $CF_DIR/config.yml, skipping tunnel setup."
    fi
fi

# Using /app/db for the database file as per the user's Dockerfile setup
if [ "$TRUST_PROXY" = "1" ]; then
    exec /app/paste -addr 0.0.0.0 -port 8080 -db /app/db/paste.db -trust-proxy "$@"
fi
exec /app/paste -addr 0.0.0.0 -port 8080 -db /app/db/paste.db "$@"
