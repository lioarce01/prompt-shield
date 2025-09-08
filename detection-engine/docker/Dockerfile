# Build stage - Optimized Go builder
FROM golang:1.21-alpine AS builder

# Build-time optimizations
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Install minimal build dependencies
RUN apk add --no-cache --update \
    git \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy go mod files first for better cache utilization
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with optimizations for size and speed
RUN go build -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
    -trimpath \
    -o detection-engine \
    ./cmd/server

# Production stage - Minimal Alpine runtime for better compatibility
FROM alpine:3.18

# Install minimal runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    wget \
    && rm -rf /var/cache/apk/* \
    && addgroup -g 1000 -S appuser \
    && adduser -u 1000 -S appuser -G appuser

# Set working directory
WORKDIR /app

# Copy the binary
COPY --from=builder /app/detection-engine ./detection-engine

# Copy only essential config files
COPY --from=builder /app/configs ./configs

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Lightweight health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=2 \
  CMD wget --no-verbose --tries=1 -q -O /dev/null http://localhost:8080/health || exit 1

# Run the application
CMD ["./detection-engine"]