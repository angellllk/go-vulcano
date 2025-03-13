# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libpcap-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -o port-scanner

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache libpcap-dev

# Copy the binary from builder
COPY --from=builder /app/port-scanner /app/port-scanner

# Set working directory
WORKDIR /app

# Run as non-root user for security
RUN adduser -D -H -h /app appuser
RUN chown appuser:appuser /app/port-scanner
USER appuser

# Command to run
ENTRYPOINT ["/app/port-scanner"]