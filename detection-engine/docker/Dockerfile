# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy source code first
COPY . .

# Initialize go module and download dependencies
RUN go mod tidy
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o detection-engine ./cmd/server

# Production stage
FROM alpine:latest

# Install ca-certificates and wget for HTTPS requests and health checks
RUN apk --no-cache add ca-certificates wget

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/detection-engine .

# Copy configuration files
COPY --from=builder /app/configs ./configs

# Create directory for logs
RUN mkdir -p /var/log/detection-engine

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./detection-engine"]