# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git make
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

# Final stage
FROM alpine:latest
WORKDIR /app

RUN apk --no-cache add ca-certificates nginx openssl

# Generate self-signed certificates
RUN mkdir -p /etc/nginx/certs && \
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/certs/server.key \
  -out /etc/nginx/certs/server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"

COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir db
COPY --from=builder /app/autentico /app/autentico


CMD ["sh", "-c", "nginx && /app/autentico"]
