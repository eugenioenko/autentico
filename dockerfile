# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git make

# Copy go.mod and go.sum for caching dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of your source code
COPY . .

# Build the Go binary using the Makefile
RUN make build

# Final stage
FROM alpine:latest

# Add CA certificates for HTTPS calls, if needed
RUN apk --no-cache add ca-certificates

# Copy the binary from the builder stage
COPY --from=builder /app/autentico /autentico

# Run the app
ENTRYPOINT ["/autentico"]
