FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
# We use go build ./... or just . since main is in the root
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s -X main.version=$(git rev-parse --short HEAD 2>/dev/null || date +%s)" -o paste .

FROM alpine:3.23

RUN apk add --no-cache curl

# Add cloudflared if needed (as per user example)
COPY --from=cloudflare/cloudflared:2025.11.1 /usr/local/bin/cloudflared /usr/local/bin/cloudflared

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/paste /app/paste

# Copy static files and templates (they are needed at runtime)
# The binary likely expects them in the current working directory or relative to it
COPY static /app/static
COPY templates /app/templates

# Setup database directory
RUN mkdir -p /app/db

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Default tunnel name (can be overridden at runtime)
ENV TUNNEL_NAME=""

ENTRYPOINT ["/entrypoint.sh"]
