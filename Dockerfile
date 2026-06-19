# ── Build stage ──────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache module downloads
COPY go.mod go.sum ./
RUN go mod download

# Build a static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/firego ./cmd/firego

# ── Runtime stage ────────────────────────────────────────────────────────
FROM alpine:3.20
RUN adduser -D -u 10001 firego
WORKDIR /app

# Binary + static dashboard
COPY --from=build /out/firego /app/firego
COPY web /app/web

# Persisted data lives here (mount a volume for persistence)
RUN mkdir -p /app/data && chown -R firego:firego /app
USER firego

ENV FIREGO_DATA=/app/data \
    FIREGO_WEB=/app/web
EXPOSE 8080

ENTRYPOINT ["/app/firego"]
