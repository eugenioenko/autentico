# Verifico — Bcrypt Worker Pool for Autentico

Verifico offloads `bcrypt.CompareHashAndPassword` calls from the Autentico master to stateless HTTP workers. This lets you scale password verification horizontally without changing the database or application architecture.

## Why

Stress tests show 90% of CPU during login goes to bcrypt. Autentico uses SQLite (single-writer), so you can't scale horizontally by adding more instances. Verifico targets the specific bottleneck: bcrypt CPU. Workers are stateless — no database, no sessions, no middleware. Just CPU for password hashing.

## Architecture

```
User → Autentico (single instance, owns SQLite)
            ↓ POST /verify {hash, password, secret}
       Verifico workers (stateless, round-robin)
            ↑ {match: true/false}
```

- Autentico dispatches bcrypt comparisons to workers via round-robin
- Workers authenticate requests using a shared secret (`crypto/subtle.ConstantTimeCompare`)
- If all workers are down, Autentico falls back to local bcrypt automatically
- When verifico is disabled (default), all bcrypt runs locally — zero overhead

## Configuration

### Master (Autentico)

| Variable | Description | Default |
|---|---|---|
| `AUTENTICO_VERIFICO_ENABLED` | Enable verifico worker pool | `false` |
| `AUTENTICO_VERIFICO_WORKERS` | Comma-separated `host:port` list of workers | (empty) |
| `AUTENTICO_VERIFICO_SECRET` | Shared secret for worker authentication | (empty) |
| `AUTENTICO_MAX_PROCS` | Limit Go runtime threads (0 = all cores) | `0` |

### Worker

| Variable | Description | Default |
|---|---|---|
| `AUTENTICO_VERIFICO_SECRET` | Shared secret (must match master) | (required) |
| `AUTENTICO_VERIFICO_URL` | Worker listen address | `http://0.0.0.0:5050` |
| `AUTENTICO_MAX_PROCS` | Limit Go runtime threads (0 = all cores) | `0` |

## CLI Commands

### `autentico verifico init`

Generate a `.env` file for a worker instance.

```bash
autentico verifico init --secret <shared-secret> --url http://0.0.0.0:5050
```

| Flag | Description | Default |
|---|---|---|
| `--secret` | Shared secret (required, also reads `AUTENTICO_VERIFICO_SECRET` env var) | — |
| `--url` | Worker listen URL | `http://0.0.0.0:5050` |
| `--output` | Directory to write `.env` into | `.` |

### `autentico verifico start`

Start a verifico worker server. Reads configuration from `.env` in the working directory.

```bash
autentico verifico start
autentico verifico start --port 6060
```

| Flag | Description | Default |
|---|---|---|
| `--port` | Override listen port (takes precedence over `AUTENTICO_VERIFICO_URL`) | port from URL or `5050` |

### `autentico verifico test`

Test connectivity and secret validation against all configured workers. Reads the master's `.env`.

```bash
autentico verifico test
```

Output:

```
Verifico is enabled with 3 worker(s).

  ✓ 10.0.0.2:5050 — reachable, secret ok (2ms)
  ✓ 10.0.0.3:5050 — reachable, secret ok (3ms)
  ✗ 10.0.0.4:5050 — unreachable, connection refused

Result: 2/3 workers healthy.
```

Two checks per worker:
1. `GET /healthz` — connectivity (is the worker reachable?)
2. `POST /ping` — secret validation (does the shared secret match?)

## Worker HTTP Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/verify` | Shared secret in body | Bcrypt hash comparison (the main workload) |
| `POST` | `/ping` | Shared secret in body | Secret validation check (lightweight) |
| `GET` | `/healthz` | None | Connectivity check |

### `POST /verify`

```json
// Request
{"hash": "$2a$10$...", "password": "user-input", "secret": "shared-secret"}

// Response (200)
{"match": true}

// Response (401) — bad secret
"unauthorized"
```

### `POST /ping`

```json
// Request
{"secret": "shared-secret"}

// Response (200)
{"status": "ok"}

// Response (401) — bad secret
"unauthorized"
```

### `GET /healthz`

```
// Response (200)
ok
```

## Setup Guide

### 1. Generate a shared secret

Use the one from `autentico init` or generate your own:

```bash
openssl rand -hex 32
```

### 2. Configure the master

Add to the master's `.env`:

```bash
AUTENTICO_VERIFICO_ENABLED=true
AUTENTICO_VERIFICO_WORKERS=worker1:5050,worker2:5050,worker3:5050
AUTENTICO_VERIFICO_SECRET=<your-shared-secret>
```

### 3. Initialize and start workers

On each worker machine:

```bash
autentico verifico init --secret <your-shared-secret> --url http://0.0.0.0:5050
autentico verifico start
```

### 4. Verify

From the master:

```bash
autentico verifico test
```

## Docker Compose Example

```yaml
services:
  autentico:
    image: autentico:latest
    command: ["start"]
    ports:
      - "9999:9999"
    environment:
      AUTENTICO_APP_URL: http://localhost:9999
      AUTENTICO_ACCESS_TOKEN_SECRET: ${ACCESS_TOKEN_SECRET}
      AUTENTICO_REFRESH_TOKEN_SECRET: ${REFRESH_TOKEN_SECRET}
      AUTENTICO_CSRF_SECRET_KEY: ${CSRF_SECRET_KEY}
      AUTENTICO_VERIFICO_ENABLED: "true"
      AUTENTICO_VERIFICO_WORKERS: verifico-1:5050,verifico-2:5050,verifico-3:5050
      AUTENTICO_VERIFICO_SECRET: ${VERIFICO_SECRET}
      AUTENTICO_MAX_PROCS: "2"
    volumes:
      - autentico-data:/data

  verifico-1:
    image: autentico:latest
    command: ["verifico", "start"]
    environment:
      AUTENTICO_VERIFICO_SECRET: ${VERIFICO_SECRET}
      AUTENTICO_VERIFICO_URL: http://0.0.0.0:5050
      AUTENTICO_MAX_PROCS: "2"

  verifico-2:
    image: autentico:latest
    command: ["verifico", "start"]
    environment:
      AUTENTICO_VERIFICO_SECRET: ${VERIFICO_SECRET}
      AUTENTICO_VERIFICO_URL: http://0.0.0.0:5050
      AUTENTICO_MAX_PROCS: "2"

  verifico-3:
    image: autentico:latest
    command: ["verifico", "start"]
    environment:
      AUTENTICO_VERIFICO_SECRET: ${VERIFICO_SECRET}
      AUTENTICO_VERIFICO_URL: http://0.0.0.0:5050
      AUTENTICO_MAX_PROCS: "2"

volumes:
  autentico-data:
```

With a `.env` file:

```bash
ACCESS_TOKEN_SECRET=...
REFRESH_TOKEN_SECRET=...
CSRF_SECRET_KEY=...
VERIFICO_SECRET=<output of openssl rand -hex 32>
```

## Kubernetes Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: verifico
spec:
  replicas: 3
  selector:
    matchLabels:
      app: verifico
  template:
    metadata:
      labels:
        app: verifico
    spec:
      containers:
        - name: verifico
          image: autentico:latest
          args: ["verifico", "start"]
          ports:
            - containerPort: 5050
          env:
            - name: AUTENTICO_VERIFICO_SECRET
              valueFrom:
                secretKeyRef:
                  name: verifico-secret
                  key: secret
            - name: AUTENTICO_VERIFICO_URL
              value: http://0.0.0.0:5050
          readinessProbe:
            httpGet:
              path: /healthz
              port: 5050
          livenessProbe:
            httpGet:
              path: /healthz
              port: 5050
---
apiVersion: v1
kind: Service
metadata:
  name: verifico
spec:
  selector:
    app: verifico
  ports:
    - port: 5050
      targetPort: 5050
```

Then on the Autentico master:

```
AUTENTICO_VERIFICO_ENABLED=true
AUTENTICO_VERIFICO_WORKERS=verifico:5050
AUTENTICO_VERIFICO_SECRET=<from secret>
```

Kubernetes Service round-robins across pods, so a single `verifico:5050` entry is sufficient. Autentico's built-in round-robin works across multiple entries if you prefer explicit pod addresses.

## Behavioral Details

- **Worker selection:** Round-robin via atomic counter. Deterministic, lock-free, evenly distributed.
- **Failover:** If a worker fails, the next worker in the pool is tried. If all fail, Autentico falls back to local bcrypt with a warning log.
- **Timeout:** Worker HTTP client has a 5-second timeout.
- **Graceful shutdown:** Workers handle SIGINT/SIGTERM and drain in-flight requests.
- **Secret comparison:** Uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

## Toggling On/Off

Set `AUTENTICO_VERIFICO_ENABLED=false` to disable verifico without removing the worker configuration. All bcrypt reverts to local. Set it back to `true` to re-enable — no restart of workers needed, only restart of the master.

## Benchmarking on a Single Machine

Use `AUTENTICO_MAX_PROCS` to constrain cores and prove the offloading mechanism:

```bash
# Baseline: Autentico uses 2 cores, no workers
AUTENTICO_MAX_PROCS=2 autentico start

# With workers: Autentico on 2 cores, workers use the rest
AUTENTICO_MAX_PROCS=2 autentico start
AUTENTICO_MAX_PROCS=4 autentico verifico start --port 5050
AUTENTICO_MAX_PROCS=4 autentico verifico start --port 5051
```

On a 16-core machine: Autentico gets 2 cores for HTTP/DB/JWT, workers get the remaining cores for bcrypt. Same total CPU, but Autentico's cores never compete with bcrypt.

Note: running workers on the same machine doesn't improve total throughput — it adds HTTP overhead. The benchmark proves the mechanism works. In production, workers run on separate machines.

## Security Model

- Workers run on a **private network** (VPC, Docker overlay, Kubernetes pod network).
- Authentication is a **shared secret** sent in each request body.
- **No TLS required** at the application level — the password already traveled over the public internet to reach Autentico. One more hop on a private network is no worse.
- For Kubernetes environments where pod-to-pod encryption is required, use a service mesh (Istio, Linkerd) — that's an infrastructure concern, not an application concern.

## Design History

See the bottom of this document for the full design conversation that led to this architecture, exploring CQRS, Postgres, child processes, mTLS, AES encryption, and sticky sessions before arriving at the current design.

### Alternatives Considered

| Approach | Why we moved on |
|---|---|
| CQRS with LiteFS replicas | Solves general scaling, but bottleneck is one function, not read/write distribution |
| Postgres | Doesn't solve bcrypt CPU — it runs on the app instance regardless of database |
| Child processes | Go already parallelizes across all cores via goroutines — no benefit on same machine |
| Sticky sessions / user sharding | Requires shared lookup table, which requires shared database |
| mTLS | Operationally heavy (CA, cert rotation) for a boolean endpoint |
| AES symmetric encryption | Reimplementing TLS poorly |
| gRPC | One endpoint, one request-response — `net/http` is simpler with no dependencies |
