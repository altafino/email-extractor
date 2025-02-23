# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/email-service ./cmd/server

# Final stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy the binary from builder
COPY --from=builder /app/email-service .

# Copy config directory
COPY config /app/config

# Create directories for logs and attachments
RUN mkdir -p /data/attachments /var/log

# Create volume for attachments and logs
VOLUME ["/data/attachments", "/var/log"]

# Expose the application port
EXPOSE 8080

# Run the application
CMD ["/app/email-service"] 