# ==========================================
# NFCheck API — Production Multi-Stage Build
# ==========================================

# ── Stage 1: Build binary ─────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build statically-linked, stripped production binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=2.0.0" \
    -o nfchecker ./cmd/server/

# ── Stage 2: Minimal Runtime ──────────────
FROM alpine:3.19

# ca-certificates: TLS verification for outgoing HTTPS requests to Netflix & proxies
# tzdata: timezone data for scheduling & timestamps
# libarchive-tools (provides bsdtar) & 7zip (provides 7z): external utilities for RAR/archive extraction
RUN apk --no-cache add ca-certificates tzdata libarchive-tools 7zip

WORKDIR /app

# Copy compiled binary from builder stage
COPY --from=builder /app/nfchecker .

# Default API port (Render overrides this dynamically via PORT env var)
EXPOSE 8080

# Production default environment variables
# PORT: HTTP listen port (Render sets this automatically, e.g., 10000)
# WORKERS: Concurrent worker goroutines (defaults to 4 to prevent CPU/RAM exhaustion)
# RATE_PER_MIN: Rate limit per minute (0 = unlimited, default = 1000)
# JSON_LOG: Structured JSON logging (true/false)
ENV PORT=8080 \
    WORKERS=4 \
    RATE_PER_MIN=1000 \
    JSON_LOG=false

# Direct exec invocation enables PID 1 signal forwarding for clean SIGTERM graceful shutdown
ENTRYPOINT ["./nfchecker"]
