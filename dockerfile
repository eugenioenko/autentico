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


RUN apk --no-cache add ca-certificates
RUN mkdir db
COPY --from=builder /app/autentico /app/autentico


# Run the app
ENTRYPOINT ["/app/autentico"]
