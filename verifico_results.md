# Verifico Benchmark Results

## Test Environment

- **Machine:** Laptop, 8 cores
- **k6:** Docker, same machine (shares CPU)
- **Test:** 50 VUs, 1 minute, no sleep, full PKCE auth code flow
- **Rate limiting:** Disabled
- **Anti-timing delay:** Disabled
- **Error rate:** 0% in all tests

## Finding the Ceiling (8 cores, no sleep)

| VUs | Throughput | Login p95 | Login avg | Iteration avg |
|---|---|---|---|---|
| 50 | 24.8 iter/s | 681ms | 417ms | 1.97s |
| 100 | 24.0 iter/s | 1,490ms | 797ms | 3.99s |

- Throughput plateaus at ~25 iter/s regardless of VU count.
- More VUs just adds latency without increasing throughput — classic saturated system.
- **50 VUs no-sleep** is the sweet spot: latency is noticeable but the system isn't collapsed.

## Vertical Scaling (50 VUs, no sleep)

Single Autentico instance, no verifico, varying `AUTENTICO_MAX_PROCS`.

| Cores | Throughput | Login avg | Login p95 | Token p95 | Refresh p95 | Iteration avg |
|---|---|---|---|---|---|---|
| 1 | 7.93 iter/s | 1,850ms | 5,090ms | 2,150ms | 2,840ms | 6.23s |
| 2 | 10.83 iter/s | 990ms | 2,110ms | 2,140ms | 2,920ms | 4.50s |
| 4 | 11.20 iter/s | 869ms | 1,870ms | 2,170ms | 3,060ms | 4.35s |
| 6 | 14.61 iter/s | 670ms | 1,710ms | 1,970ms | 2,710ms | 3.33s |
| 8 | 24.81 iter/s | 417ms | 681ms | 725ms | 1,020ms | 1.97s |

```
Throughput (iter/s) vs Cores — Vertical Scaling

  25 |                                                    ●  8 cores
     |
  20 |
     |
  15 |                                        ●  6 cores
     |
  10 |          ●  2c    ●  4 cores
     |
   5 |●  1 core
     |
   0 +-----+-----+-----+-----+-----+-----+-----+-----+
     0     1     2     3     4     5     6     7     8
                          Cores
```

### Vertical Scaling Observations

- **Diminishing returns from 2→4 cores:** throughput barely moves (10.8 → 11.2 iter/s, +3%). Adding cores doesn't help in this range.
- **Big jump at 6→8 cores:** throughput nearly doubles (14.6 → 24.8 iter/s, +70%).
- **1→2 cores is the most impactful jump:** throughput +37%, login p95 drops 58%.
- **The 2-4 core plateau** is likely SQLite write contention — extra CPU can't help when goroutines are blocked on the single-writer lock.

## Horizontal Scaling with Verifico (50 VUs, no sleep)

All processes share all CPU cores freely (OS scheduler decides). Core budget is simulated via `AUTENTICO_MAX_PROCS` for the main process and number of worker processes (each with its own `MAX_PROCS`).

Notation: `A(n)` = Autentico with MAX_PROCS=n, `W(n)` = worker with MAX_PROCS=n.

| Budget | Config | Throughput | Login avg | Login p95 | Token p95 | Refresh p95 |
|---|---|---|---|---|---|---|
| 2 cores | 1A(1) + 1W(1) | 11.52 iter/s | 3,270ms | 4,190ms | 1,660ms | 2,180ms |
| 4 cores | 1A(1) + 3W(1) | **15.80 iter/s** | 706ms | 1,260ms | 1,100ms | 1,480ms |
| 4 cores | 2A(2) + 2W(1) | 6.28 iter/s | 1,680ms | 3,180ms | 2,840ms | 3,810ms |
| 6 cores | 2A(2) + 4W(1) | **16.33 iter/s** | 679ms | 1,280ms | 1,180ms | 1,470ms |
| 6 cores | 1A(1) + 5W(1) | 7.11 iter/s | 1,330ms | 2,550ms | 2,800ms | 3,940ms |
| 8 cores | 4A(4) + 4W(1) | 14.78 iter/s | 724ms | 1,780ms | 1,560ms | 1,800ms |
| 8 cores | 4A(4) + 2W(2) | **15.13 iter/s** | 700ms | 1,400ms | 1,500ms | 1,630ms |
| 8 cores | 2A(2) + 6W(1) | 9.02 iter/s | 1,020ms | 2,240ms | 2,630ms | 3,670ms |
| 8 cores | 2A(2) + 3W(2) | 7.49 iter/s | 1,280ms | 2,560ms | 2,650ms | 3,910ms |

## Vertical vs Horizontal Comparison

| Budget | Vertical | Best Horizontal | Config | Delta |
|---|---|---|---|---|
| 2 cores | 10.83 iter/s | 11.52 iter/s | 1A(1) + 1W(1) | **+6%** |
| 4 cores | 11.20 iter/s | **15.80 iter/s** | 1A(1) + 3W(1) | **+41%** |
| 6 cores | 14.61 iter/s | **16.33 iter/s** | 2A(2) + 4W(1) | **+12%** |
| 8 cores | **24.81 iter/s** | 15.13 iter/s | 4A(4) + 2W(2) | **-39%** |

```
Throughput (iter/s) — Vertical vs Horizontal (best config per budget)

  25 |                                                    ■  8V
     |
  20 |
     |
  15 |                    ●  4H          ●  6H    ●  8H
     |                                        ■  6V
  10 |■  2V   ●  2H      ■  4V
     |
   5 |
     |
   0 +-----+-----+-----+-----+-----+-----+-----+-----+
     0     1     2     3     4     5     6     7     8
                    Total Cores (■ vertical  ● horizontal)
```

## 8-Core Horizontal Breakdown

All 4 configurations tested at 8-core budget:

```
Throughput (iter/s) — 8-Core Horizontal Configs

  16 |                    ●  4A+2W(2)
  15 |●  4A+4W(1)
     |
  12 |
     |
   9 |          ●  2A+6W(1)
     |                              ●  2A+3W(2)
   6 |
     |
   3 |
     |
   0 +----------+----------+----------+----------+
     4A+4W(1)  2A+6W(1)  4A+2W(2)  2A+3W(2)
```

| Config | Throughput | Notes |
|---|---|---|
| 4A(4) + 4W(1) | 14.78 iter/s | Best single-core-worker config |
| 4A(4) + 2W(2) | 15.13 iter/s | Best overall — fewer workers, more cores each |
| 2A(2) + 6W(1) | 9.02 iter/s | Too many workers, main process starved |
| 2A(2) + 3W(2) | 7.49 iter/s | Same 2A bottleneck, dual-core workers don't help |

## Key Observations

### Verifico helps most at 4 cores (+41%)

The biggest win is at 4 cores where vertical scaling hits the SQLite write contention plateau (10.83 → 11.20 iter/s, only +3% for doubling cores). Verifico breaks through this: 1A(1)+3W(1) reaches 15.80 iter/s — a 41% improvement over 4-core vertical. The main process stays single-threaded and focused on HTTP+DB while workers handle bcrypt in parallel.

### 1A vs 2A depends on worker count

At 4 cores, 1A+3W (15.80) crushes 2A+2W (6.28). But at 6 cores, 2A+4W (16.33) crushes 1A+5W (7.11). The pattern: a single Autentico core can feed ~3 workers before becoming the bottleneck. Beyond that, you need a second core for the main process.

### Optimal worker-to-Autentico ratio

| Config | Ratio (W:A cores) | Throughput |
|---|---|---|
| 1A(1) + 3W(1) | 3:1 | 15.80 |
| 2A(2) + 4W(1) | 2:1 | 16.33 |
| 4A(4) + 2W(2) | 1:1 | 15.13 |
| 4A(4) + 4W(1) | 1:1 | 14.78 |

The sweet spot is 2-3 worker cores per Autentico core. Below that, bcrypt capacity is the bottleneck. Above that, the main process can't push work fast enough.

### Dual-core workers don't help much

At 8 cores, 4A+2W(2) = 15.13 vs 4A+4W(1) = 14.78 — virtually identical. Bcrypt is single-threaded per hash, so giving a worker 2 cores doesn't speed up individual hashes. The slight edge is likely from the Go runtime having a spare core for GC and HTTP serving.

### 8-core vertical still wins overall

At 8 cores, vertical (24.81 iter/s) beats the best horizontal config (15.13 iter/s) by 64%. On a single machine with shared memory and no network overhead, the Go scheduler can dynamically balance all 8 cores between bcrypt and HTTP/DB work. Verifico adds process boundaries and HTTP overhead between workers.

### Where verifico makes sense

Verifico's value is clearest when:
1. **You're CPU-constrained at 2-6 cores** — the 4-core sweet spot delivers +41% over vertical
2. **You have separate machines** — workers on dedicated hardware avoid the shared-CPU penalty
3. **You want to scale bcrypt independently** — add worker machines without touching the main server

On a single 8-core machine, vertical scaling is simpler and faster.
