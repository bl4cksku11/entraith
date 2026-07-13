# syntax=docker/dockerfile:1

# ── build stage ───────────────────────────────────────────────────────────────
FROM golang:1.24 AS build
WORKDIR /src
# Cache modules separately so source edits don't re-download everything.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go build (modernc sqlite, no CGO).
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /entraith ./cmd/entraith

# ── runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN adduser -D -H entraith && mkdir -p /data && chown entraith /data
COPY --from=build /entraith /usr/local/bin/entraith
# Demo config only (secure_cookies = false, plain HTTP on localhost). For a real
# engagement, mount your own config over this path or override the entrypoint.
COPY engagement.docker.conf /etc/entraith/engagement.conf
USER entraith
EXPOSE 8443
# Assumes the in-container listener is plain HTTP (TLS terminated by the front
# proxy), which matches the shipped demo config and the deployment guidance.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8443/health || exit 1
ENTRYPOINT ["entraith", "server", "--config", "/etc/entraith/engagement.conf"]
