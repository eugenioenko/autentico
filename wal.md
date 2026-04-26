# SQLite WAL Mode Benchmarks

## Context

Autentico uses SQLite with a single-writer connection pool (`MaxOpenConns=1`). This document captures the benchmarks that determined whether enabling WAL (Write-Ahead Logging) mode improves throughput.

All tests: k6 (Docker), 200 and 500 virtual users, 30 seconds, no sleep, full PKCE auth code flow (authorize → login → token → introspect → refresh). Rate limiting and anti-timing delay disabled. 16-core desktop machine, all CPUs available.

## What WAL Does

By default, SQLite uses rollback journal mode. Every write locks the entire database file, blocking all readers until the write completes. WAL mode changes this: readers see a consistent snapshot of the database while a writer appends to a separate log file. Multiple readers can proceed concurrently, and a single writer does not block them.

The change is a single PRAGMA added at connection open time:

```sql
PRAGMA journal_mode = WAL;
```

No other code changes are needed. The single-connection pool (`MaxOpenConns=1`) is preserved.

## Why Not a Read/Write Pool Split?

An earlier experiment (PR #300) paired WAL with a split connection pool: 1 dedicated writer + N reader connections. The hypothesis was that separating read and write connections would allow concurrent reads to proceed without waiting behind writes.

**The split pool was a regression at high concurrency.** At 200 VUs:

| Configuration | Throughput | Login p95 |
|---|---|---|
| WAL + single pool | 113 iter/s | ~780ms |
| WAL + split pool (4 readers) | 35 iter/s | 1.47s |

The split pool is 3× slower. The reason: with a single pool, reads and writes naturally serialize. This acts as backpressure — goroutines queue up waiting for the one connection, and by the time they get it, contention on the SQLite writer lock is low. With separate read connections, all 200 goroutines complete their reads simultaneously, then pile up on the single writer connection at once, creating a contention storm.

The single pool's serialization is a feature, not a bug. It aligns Go-level concurrency with SQLite's single-writer architecture.

## Benchmark Results

### 200 VUs (30s)

| Configuration | Iterations | Throughput | Login p95 | Token p95 | Refresh p95 |
|---|---|---|---|---|---|
| v1.6.18 release (WAL, single pool) | 3,510 | 113 iter/s | 781ms | 815ms | 985ms |
| WAL + split pool (4 readers) | 1,306 | 37.5 iter/s | 1,470ms | 1,990ms | 3,440ms |

### 500 VUs (30s)

| Configuration | Iterations | Throughput | Login p95 | Token p95 | Refresh p95 |
|---|---|---|---|---|---|
| WAL + split pool (4 readers) | 1,539 | 37.5 iter/s | 3,340ms | 4,560ms | 8,680ms |

## Block Profile Analysis

A Go block profile under load (4 GOMAXPROCS, 486 iterations) revealed that **all** contention is at `database/sql.(*DB).conn` — goroutines waiting for a connection from the pool.

**Reads account for 65% of total contention, writes 35%.**

Top contention sites:

| Cycles (B) | Type | Operation |
|---|---|---|
| 788 | WRITE | `session.CreateSession` (token handler) |
| 765 | READ | `client.ClientByClientID` (token handler) |
| 747 | WRITE | `token.CreateToken` (token handler) |
| 480 | READ | `session.SessionByIDIncludingDeactivated` (refresh) |
| 467 | READ | `user.UserByID` (refresh) |
| 459 | WRITE | revoke old token (token handler) |

Each auth flow iteration makes 5 HTTP requests with 4-5 writes per iteration (IDP session, auth code consume, session, token, audit log).

## Why WAL Alone Is Sufficient

With a single connection pool, WAL mode still helps because:

1. **No reader-writer blocking**: Under rollback journal mode, a write acquires an exclusive lock that blocks all readers. With WAL, readers see the last committed state while a write is in progress. The single Go connection pool still serializes access, but the underlying SQLite operations complete faster because they don't contend at the file-lock level.

2. **Crash recovery**: WAL mode provides better crash recovery characteristics — partial writes don't corrupt the main database file.

3. **No write amplification**: Rollback journal mode copies pages to the journal before modifying them (write-ahead of the old data). WAL writes new data to the log and checkpoints lazily. This reduces I/O per write.

## Configuration

```bash
# No new environment variables needed.
# WAL mode is enabled automatically at startup.
```
