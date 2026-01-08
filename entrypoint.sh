#!/bin/sh
set -eu

# Cloudflared tunnel support
TUNNEL_NAME="${TUNNEL_NAME:-}"

if [ -n "$TUNNEL_NAME" ]; then
    if [ -f "/root/.cloudflared/config.yml" ]; then
        cloudflared tunnel --config /root/.cloudflared/config.yml run "$TUNNEL_NAME" &

        echo "Waiting for Cloudflared tunnel to connect..."
        for i in $(seq 1 30); do
            if cloudflared tunnel info "$TUNNEL_NAME" > /dev/null 2>&1; then
                echo "Tunnel connected!"
                break
            fi
            sleep 2
        done
    else
        echo "Cloudflare tunnel configuration not found at /root/.cloudflared/config.yml, skipping tunnel setup."
    fi
fi

# Run the paste application
# Using /app/db for the database file as per the user's Dockerfile setup
exec /app/paste -addr 0.0.0.0 -port 8080 -db /app/db/paste.db "$@"
