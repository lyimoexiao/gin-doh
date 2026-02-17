# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Enable Go toolchain auto-download for version requirements
ENV GOTOOLCHAIN=auto

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version info
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} \
              -X main.gitCommit=${GIT_COMMIT} \
              -X main.buildTime=${BUILD_TIME} \
              -X main.goVersion=$(go version | awk '{print $3}')" \
    -o /gin-doh ./cmd/server

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' appuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /gin-doh /app/gin-doh
COPY --from=builder /app/config.yaml /app/config.yaml

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Default config path
ENV CONFIG_PATH=/app/config.yaml

# Run the binary
ENTRYPOINT ["/app/gin-doh"]
CMD ["-config", "/app/config.yaml"]
