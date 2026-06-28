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
COPY engagement.docker.conf /etc/entraith/engagement.conf
USER entraith
EXPOSE 8443
ENTRYPOINT ["entraith", "server", "--config", "/etc/entraith/engagement.conf"]
