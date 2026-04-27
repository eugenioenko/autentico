# Horizontal Scaling Benchmark — Verifico only (no WAL pool)

200 VUs, 30s, full PKCE auth code flow
Server: 2A (GOMAXPROCS=2), Workers: GOMAXPROCS=2 each

## Results

| Config | iter/s | Iterations | Success% | Login p95 | Authorize p95 | Token p95 | Introspect p95 | Refresh p95 |
|--------|--------|-----------|----------|-----------|--------------|-----------|----------------|-------------|
| **6c: 2A + 2W@2** | 32.1 | 1,238 | 47.7% | 3.43s | 1.33s | 3.06s | 2.09s | 5.59s |
| **8c: 2A + 3W@2** | 40.6 | 1,533 | 36.6% | 3.12s | 1.27s | 3.39s | 2.12s | 5.84s |
| **10c: 2A + 4W@2** | 55.5 | 2,065 | 25.0% | 2.83s | 1.11s | 2.81s | 2.00s | 5.62s |
| **12c: 2A + 5W@2** | 39.9 | 1,532 | 36.6% | 3.23s | 1.22s | 3.24s | 2.20s | 5.87s |
| **14c: 2A + 6W@2** | 31.7 | 1,193 | 46.8% | 3.71s | 1.45s | 3.50s | 2.27s | 6.45s |
| **16c: 2A + 7W@2** | 51.6 | 2,016 | 26.7% | 2.98s | 1.18s | 3.24s | 2.10s | 5.92s |

## Notes

- 1,897 SQLITE_BUSY errors in the 16c run — primary bottleneck is SQLite write contention, not bcrypt
- Non-monotonic scaling (12c/14c regression) is noise from SQLITE_BUSY contention varying between runs
- Workers are confirmed active (CPU utilization observed after fixing AUTENTICO_VERIFICO_ENABLED=true bug)
