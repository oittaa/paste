# Paste

![Paste UI](static/screenshot.png)

A simple, fast, and secure pastebin application written in Go.

## Features

- **Lightweight**: Minimal dependencies, fast performance.
- **Secure**: Built with security best practices.
- **Code Highlighting**: Powered by Highlight.js.
- **Docker Ready**: Easy deployment with Docker and Docker Compose.
- **Cloudflare Tunnel Support**: Built-in support for `cloudflared`.

## Getting Started

### Prerequisites

- Go 1.25+
- Docker (optional)

### Running Locally

```bash
git clone https://github.com/oittaa/paste.git
cd paste
go build -o paste .
./paste -addr 0.0.0.0 -port 8080 -db paste.db
```
The application will be available at `http://localhost:8080`.

### Configuration Options

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `0.0.0.0` | Listen address |
| `-port` | `8080` | Listen port |
| `-db` | `pastes.db` | SQLite DB file (use `:memory:` for in-mem) |
| `-maxsize` | `1048576` | Maximum paste size in bytes |
| `-expire-duration` | `720h` | Paste expiration duration |
| `-rate-limit` | `60` | Max paste creates per IP per window (`0` disables) |
| `-rate-window` | `1m` | Rate limit window |
| `-max-pastes` | `100000` | Maximum stored pastes (`0` disables) |
| `-max-storage` | `1073741824` | Maximum total paste bytes (`0` disables) |
| `-trust-proxy` | `false` | Trust `CF-Connecting-IP` and `X-Forwarded-For` |

Run `./paste -help` for the full list of options.

Set `-trust-proxy` when the process is behind Cloudflare or another reverse proxy. Without that flag, rate limits use the TCP peer address.

## Deployment with Docker

### Docker Compose (Recommended)

**Basic deployment:**
```bash
docker-compose up --build -d
```

**With Cloudflare Tunnel:**
1. Configure `~/.cloudflared/config.yml`.
2. Uncomment the tunnel configuration in `docker-compose.yml`.
3. Run `docker-compose up -d`.

### Docker CLI

```bash
docker build -t paste .
# Standard
docker run -d -p 8080:8080 -v $(pwd)/data:/app/db paste
# With Tunnel
docker run -d --name paste -e TUNNEL_NAME=my-paste-tunnel \
  -v "$HOME/.cloudflared":/home/paste/.cloudflared:ro -v "$HOME/paste-db":/app/db paste
```

> **Note**: Cloudflare tunnel is optional. If `TUNNEL_NAME` is not set, the app starts normally.
