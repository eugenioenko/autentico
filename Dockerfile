# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM golang:1.24-bookworm AS builder

# Install Node.js 22.x and pnpm 9 (needed for admin-ui build)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g pnpm@10 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install swag CLI (matches project's swag dependency version)
RUN go install github.com/swaggo/swag/cmd/swag@v1.16.4

WORKDIR /app

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Cache pnpm dependencies separately for better layer caching
COPY admin-ui/package.json admin-ui/pnpm-lock.yaml ./admin-ui/
COPY account-ui/package.json account-ui/pnpm-lock.yaml ./account-ui/
RUN cd admin-ui && pnpm install --frozen-lockfile
RUN cd account-ui && pnpm install --frozen-lockfile

# Copy the rest of the source
COPY . .

# Build: generates swagger docs, builds admin UI, compiles Go binary
RUN CGO_ENABLED=0 make build

# ── Stage 2: runner ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runner

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/autentico ./autentico

# db/ holds the SQLite database — mount a volume to persist data across restarts
VOLUME ["/app/db"]

EXPOSE 9999

ENTRYPOINT ["./autentico", "start"]
