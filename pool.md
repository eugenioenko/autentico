# SQLite Connection Pool Benchmarks

## Context

Autentico uses SQLite with WAL mode and a split connection pool: a single writer (MaxOpenConns=1) serializes all mutations, and a configurable reader pool enables concurrent reads. This document captures the benchmarks that determined the default pool sizes.

All tests: k6, 100 virtual users, 30 seconds, no sleep, full PKCE auth code flow (authorize → login → token → introspect → refresh). Rate limiting and anti-timing delay disabled. 16-core desktop machine.

## Block Profile: Where Time Is Spent

A Go block profile under load (4 GOMAXPROCS, 486 iterations) revealed that **every** contention point is at `database/sql.(*DB).conn` — goroutines waiting for a connection from the pool.

**Reads account for 65% of total contention, writes 35%.**

Top contention sites:

| Cycles (B) | Hits | Type | Operation |
|-----------|------|------|-----------|
| 788 | 971 | WRITE | `session.CreateSession` (token handler) |
| 765 | 972 | READ | `client.ClientByClientID` (token handler) |
| 747 | 972 | WRITE | `token.CreateToken` (token handler) |
| 480 | 486 | READ | `session.SessionByIDIncludingDeactivated` (refresh) |
| 467 | 486 | READ | `user.UserByID` (refresh) |
| 459 | 486 | WRITE | revoke old token (token handler) |
| 426 | 485 | READ | `client.ClientByClientID` (authorize) |
| 421 | 486 | WRITE | `user.AuthenticateUser` update (login) |
| 418 | 486 | READ | `user.UserByID` (introspect) |
| 383 | 486 | WRITE | `audit.Log` (login) |
| 368 | 486 | WRITE | `idpsession.CreateIdpSession` (login) |

Each auth flow iteration makes 5 HTTP requests. Only login runs bcrypt. The other four involve SQLite reads and writes that don't burn CPU — they spend wall time waiting for connections and the writer lock.

## WAL Mode + Read/Write Pool Split

Before the split, a single `database/sql` pool serialized all operations (reads AND writes) through one connection. WAL mode allows concurrent readers alongside a single writer, but the single pool negated this.

The split: 1 writer connection (eliminates SQLITE_BUSY errors) + N reader connections (concurrent reads via WAL).

### Before vs After (vertical scaling, no read pool tuning)

| Cores | Original (no WAL) iter/s | Double pool iter/s | Login p95 | Errors |
|-------|--------------------------|--------------------|-----------|--------|
| 1 | 10.49 | 44.1 | 670ms | 0% |
| 2 | 16.71 | 41.8 | 709ms | 0% |
| 4 | 20.11 | 39.8 | 697ms | 0% |
| 6 | — | 38.3 | 717ms | 0% |

The original setup had a throughput ceiling at ~20 iter/s (4 cores). The double pool eliminates all errors and pushes throughput to 44 iter/s. Login p95 dropped from seconds to ~700ms.

Throughput is flat or slightly declining with more cores — the single writer is now the ceiling. More cores means more goroutines finishing reads faster and piling up on the writer lock.

## Read Pool Size: Does It Matter?

### All CPUs available (GOMAXPROCS=16)

| Read Pool | Throughput | Login p95 | Refresh p95 |
|-----------|-----------|-----------|-------------|
| 2 | 29.3 iter/s | 1,020ms | 2,210ms |
| **4** | **44.2 iter/s** | **692ms** | **1,410ms** |
| 6 | 37.9 iter/s | 798ms | 1,610ms |

Pool size 4 is the sweet spot: 50% more throughput than pool 2. Pool 6 is slower than 4 — more concurrent readers flood the writer lock.

### Constrained to 2 CPUs (GOMAXPROCS=2)

| Read Pool | Throughput | Login p95 | Refresh p95 |
|-----------|-----------|-----------|-------------|
| 2 | 15.2 iter/s | 2,900ms | 4,190ms |
| 4 | 14.3 iter/s | 2,690ms | 4,330ms |
| 6 | 14.0 iter/s | 2,770ms | 4,810ms |

At 2 cores, the read pool size barely matters — all three are within noise. There isn't enough CPU to benefit from extra readers.

## Why 4 Is the Default Cap

The auto-calculation: `min(available CPUs, 4)` with a floor of 2.

- **2-core VPS**: gets 2 readers (pool size irrelevant at this CPU count)
- **4-core machine**: gets 4 readers (the measured sweet spot)
- **16-core machine**: gets 4 readers (not 16, which was slower)

Admins can override with `AUTENTICO_DB_READ_POOL_SIZE` for their specific workload.

## Why More Readers Hurts

Each auth flow has 4-5 writes per iteration (IDP session, auth code consume, session, token, audit log). With more readers, read operations complete faster, causing goroutines to reach write operations sooner. This creates more concurrent contention on the single writer lock, reducing aggregate throughput.

The bcrypt computation in the login step acts as an accidental rate limiter — by slowing individual requests, it reduces the number of concurrent writers, which paradoxically increases throughput. This was confirmed by patching bcrypt to return immediately: without bcrypt, throughput drops to ~15 iter/s at all core counts (the SQLite writer ceiling), compared to ~20 iter/s with bcrypt enabled.

## Configuration

```bash
# Maximum OS threads for Go goroutines (0 = all CPUs)
AUTENTICO_MAX_PROCS=0

# SQLite read pool size (0 = auto: min(CPUs, 4), floor 2)
AUTENTICO_DB_READ_POOL_SIZE=0
```
