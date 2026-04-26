Verifico MD

# Verifico: Designing Horizontal Scaling for Bcrypt


This document captures the design conversation that led to verifico — a bcrypt worker pool for Autentico. The path was not straight; we explored several directions before arriving at the simplest solution.


## Starting Point: The Performance Data


Stress tests with k6 showed a clear bottleneck:
- 100 virtual users: ~650ms average response time
- 500 virtual users: ~3s average response time
- 90% of CPU time during login goes to bcrypt (`CompareHashAndPassword`)


Autentico is a single-binary OAuth2/OIDC IdP using SQLite. The question was: how do you scale when one operation dominates CPU?


## First Instinct: Can We Scale Horizontally?


The initial thought was straightforward — since Autentico uses SQLite, it's impossible to scale horizontally. SQLite is single-writer, single-file. You can't just add more instances.


But wait — is the database actually the bottleneck? No. 90% of CPU is bcrypt. SQLite writes (creating sessions, tokens) are microseconds. The database isn't the problem.


## Option 1: CQRS (Command Query Responsibility Segregation)


We explored splitting reads from writes:
- **Gateway nodes** — stateless, handle bcrypt + JWT validation, no database
- **Writer node** — single instance, owns SQLite, handles all DB writes
- **Reader nodes** — SQLite replicas via LiteFS or Litestream


This is a real architecture. LiteFS (by the Fly.io team) transparently replicates SQLite across nodes using a FUSE filesystem layer. One primary handles writes, replicas stream WAL pages in near-real-time.


**Why we moved on:** CQRS solves a general scaling problem, but the bottleneck is specific. 90% of CPU is one function call. We don't need to distribute reads and writes — we need to distribute bcrypt.


## Option 2: Postgres


The "standard answer" for scaling beyond SQLite. Swap the database driver (Autentico uses `database/sql`, so it's mechanical), add connection pooling, get horizontal reads via replicas.


**Why we moved on:** Postgres doesn't solve bcrypt CPU. You'd still run `CompareHashAndPassword` on the app instance. Multiple Autentico instances behind a load balancer would spread the load, but now you're paying for full instances (DB connections, memory, middleware) when all you need is more CPU for one function.


## Option 3: Child Processes for Bcrypt


Could we spawn child processes just for bcrypt computation?


**Why this doesn't work:** Go already parallelizes bcrypt across all cores via goroutines. `GOMAXPROCS` defaults to all available CPUs. Spawning separate processes on the same machine adds overhead without benefit — the Go runtime scheduler already distributes work across OS threads.


Key insight: **on a single machine, you can't beat Go's built-in parallelism for CPU-bound work.**


## Option 4: Sticky Sessions / User Sharding


Route users to specific instances based on a lookup table — "user X lives on cluster A."


**Why we moved on:** You need a shared lookup table, which needs a shared database, which is the problem you're trying to solve. And OAuth clients, tokens, and sessions need to be accessible from any instance. A user logs in on instance A, but their token gets validated on instance B.


## The Breakthrough: Offload Just Bcrypt


Instead of scaling the whole application, scale the one function that's expensive.


The idea: Autentico stays as a single instance, owns the database, handles everything. But when it needs to verify a password, it sends the stored hash and the plaintext password to a remote worker. The worker runs `bcrypt.CompareHashAndPassword` and returns true/false.


```
User → Autentico (single instance, owns SQLite)
           ↓ (storedHash, password)
      Worker pool (stateless, no DB)
           ↑ true/false
```


Workers are trivial — one endpoint, one function call, no state. They can run on the cheapest VPS available.


## Naming


We wanted a name that fits the Italian/Spanish theme of "Autentico":
- verifico — "I verify" in Italian/Spanish


**verifico** won — it says exactly what it does and matches the parent project's language.


## Same Binary or Separate?


**Separate binary (considered first):**
- Workers would run `verifico start` and `verifico init`
- Separate repo, separate Docker image, separate release
- Cleaner separation of concerns


**Same binary (what we chose):**
- `autentico verifico start` — worker mode
- `autentico verifico init` — generate worker config
- One repo, one Docker image, one release
- The worker is ~50 lines of logic — shipping the full binary adds nothing to size
- Bcrypt dependency is already in the binary
- Simpler for users: one artifact to manage


## Protocol: gRPC vs HTTP


**gRPC (considered first):**
- Industry standard for service-to-service communication
- Protobuf, HTTP/2, streaming, codegen


**HTTP (what we chose):**
- It's one endpoint with one request-response pair
- No protobuf dependency, no codegen, no gRPC library
- Standard `net/http` on both sides
- Every language can call it
- gRPC's features (streaming, multiplexing) are irrelevant here


```
POST /verify
{"hash": "...", "password": "...", "secret": "..."}


200 {"match": true}
```


## Security: The Long Road to Simplicity


This was the most iterative part of the conversation. We went through several layers:


### Round 1: mTLS
Mutual TLS — both sides verify certificates. The "correct" answer for service-to-service auth.


**Problem:** Operationally heavy. CA management, cert generation per worker, cert distribution, cert rotation. For a boolean endpoint.


### Round 2: mTLS with Registration Token
Like `kubeadm join` — Autentico generates a one-time token, worker fetches certs automatically.


**Problem:** Still managing certs. Simpler setup, same operational burden long-term.


### Round 3: AES Symmetric Encryption
Encrypt the payload with a shared AES key.


**Problem:** Reimplementing TLS poorly. TLS already does symmetric encryption after handshake, plus handles key exchange, replay protection, and forward secrecy.


### Round 4: TLS + Shared Secret
Standard TLS for encryption, shared secret (API key) for authentication.


**Problem:** Do we even need TLS?


### Round 5: Just a Shared Secret
The password already traveled over the public internet to reach Autentico. Sending it one more hop over a private network (VPC, Docker overlay) is no worse.


Workers live on private networks. A shared secret prevents unauthorized callers. That's all you need.


For Kubernetes (where pod-to-pod traffic is unencrypted by default), use network policies or a service mesh — that's an infrastructure concern, not an application concern.


**Final answer:**
- `AUTENTICO_VERIFICO_SECRET=shared-secret` on both sides
- Private network deployment
- No TLS, no certs, no custom crypto


## The GOMAXPROCS Insight


A key realization for benchmarking: you can prove verifico works on a single machine by constraining Autentico's cores.


Go's `GOMAXPROCS` controls how many OS threads the runtime uses. By default it's all cores. Add `AUTENTICO_MAX_PROCS=N` as a bootstrap setting:


```bash
# Baseline: Autentico on 2 cores, no workers
AUTENTICO_MAX_PROCS=2 autentico start
# k6 100 VUs → slow (bcrypt competes for 2 cores)


# With verifico: Autentico on 2 cores, workers use the rest
AUTENTICO_MAX_PROCS=2 autentico start
autentico verifico start --port 5050  # each gets remaining cores
autentico verifico start --port 5051
autentico verifico start --port 5052
# k6 100 VUs → fast (bcrypt offloaded, Autentico's 2 cores free)
```


On a 16-core machine: Autentico gets 2 cores for HTTP/DB/JWT, workers get 14 cores for bcrypt. Same total CPU, but Autentico's cores never compete with bcrypt.


Note: running workers on the same machine doesn't improve total throughput over running Autentico on all 16 cores — it adds HTTP overhead. The benchmark proves the offloading mechanism works. In production, workers run on separate machines, breaking the single-machine CPU ceiling.


## Why Not Just Use Postgres?


This came up repeatedly. The answer is nuanced:


Postgres solves many scaling problems — horizontal reads, writes, failover, backups. But it doesn't solve **this** problem. Bcrypt runs on the application instance regardless of database. Multiple Autentico instances with Postgres behind a load balancer would spread bcrypt across machines, but you're paying for full application instances when all you need is CPU for one function.


Verifico workers are the cheapest VPS you can find. No database connections, no memory for caching, no middleware. Just CPU.


That said, Postgres support would be valuable for other reasons (operational tooling, backups, existing infrastructure). It's complementary, not competing.


## Final Design


```
AUTENTICO_VERIFICO_WORKERS=worker1:5050,worker2:5050
AUTENTICO_VERIFICO_SECRET=shared-secret
AUTENTICO_MAX_PROCS=N
```


- Same binary: `autentico verifico start --port 5050`
- One HTTP endpoint: `POST /verify`
- Shared secret for authentication
- Private network, no TLS
- Falls back to local bcrypt if all workers are down
- Backwards compatible: no workers configured = works as today


## Open Questions


- Should `GenerateFromPassword` (signup/password change) also be offloaded?
- Round-robin vs least-connections for worker selection?
- Admin UI: read-only status panel showing worker health?



