# Verifico Benchmark Plan — 32-Core Machine

## Goal

Measure how Autentico + verifico scales horizontally on a machine with enough cores that the test client (k6) doesn't compete for CPU. This simulates a Kubernetes cluster where Autentico runs on a 2-core node and worker nodes are added incrementally.

On the laptop (8 cores), k6 competing for CPU distorted results — configs using 8 total GOMAXPROCS performed worse than configs using 6, purely because k6 was starved. With 32 cores that problem disappears.

## Prerequisites

1. **Build the binary** from the repo root:
   ```bash
   make build
   ```

2. **Docker** must be available (k6 runs in Docker).

3. **Create `.env`** if not present:
   ```bash
   ./autentico init
   ```

4. **Edit `.env`** — set these values for benchmarking:
   ```
   AUTENTICO_RATE_LIMIT_RPS=0
   AUTENTICO_RATE_LIMIT_RPM=0
   AUTENTICO_CSRF_SECURE_COOKIE=false
   AUTENTICO_ANTI_TIMING_MIN_MS=0
   AUTENTICO_ANTI_TIMING_MAX_MS=0
   AUTENTICO_VERIFICO_ENABLED=true
   AUTENTICO_VERIFICO_SECRET=benchmarksecret123
   ```

5. **First run setup** — start the server once to create the DB and onboard:
   ```bash
   ./autentico start
   ```
   - Open http://localhost:9999 in a browser
   - Complete onboarding: create admin user with username `admin`, password `asdf123`
   - Go to Admin UI → Settings:
     - Set `account_lockout_max_attempts` to `0`
     - Set `sso_session_idle_timeout` to `0`
   - Go to Admin UI → Clients → Create:
     - Client ID: `stress-test`
     - Client Type: `public`
     - Grant Types: `authorization_code`, `refresh_token`
     - Scopes: `openid profile email offline_access`
     - Redirect URI: `http://localhost:8080/stress/callback`
     - Auth Method: `none`
   - Stop the server (Ctrl+C)

6. **Verify the flow works** before running the full benchmark:
   ```bash
   # Start server
   ./autentico start &
   sleep 2

   # Run smoke test (single iteration)
   docker run --rm -i --network=host \
     -v "$(pwd)/stress:/scripts" \
     -e BASE_URL=http://localhost:9999 \
     -e USERNAME=admin -e PASSWORD=asdf123 \
     -e CLIENT_ID=stress-test \
     -e REDIRECT_URI=http://localhost:8080/stress/callback \
     grafana/k6 run /scripts/debug.js

   # Kill server
   kill %1
   ```
   All checks should pass. If login returns 403, double-check `AUTENTICO_CSRF_SECURE_COOKIE=false`.

## Run the Benchmark

```bash
bash stress/run-k8s-scaling.sh
```

This runs 14 tests (~14 minutes total):

### Part 1: Vertical Scaling Baseline (no verifico)
Single Autentico instance, no workers. Establishes the baseline at each core count.

| Test | Config | Purpose |
|---|---|---|
| 1 | 2 cores | K8s node baseline |
| 2 | 4 cores | |
| 3 | 8 cores | |
| 4 | 16 cores | |
| 5 | 32 cores | Machine ceiling |

### Part 2: K8s Simulation (2-core Autentico + N 2-core worker nodes)
Autentico fixed at MAX_PROCS=2. Workers added incrementally, each with MAX_PROCS=2 (simulating 2-core k8s nodes).

| Test | Config | Simulated Nodes |
|---|---|---|
| 6 | 2A(2) + 1W(2) | 2 nodes |
| 7 | 2A(2) + 2W(2) | 3 nodes |
| 8 | 2A(2) + 3W(2) | 4 nodes |
| 9 | 2A(2) + 4W(2) | 5 nodes |
| 10 | 2A(2) + 6W(2) | 7 nodes |
| 11 | 2A(2) + 8W(2) | 9 nodes |

### Part 3: Best Configs Retest
Re-run the laptop's best configs on 32 cores to see if they improve without CPU contention.

| Test | Config | Laptop result |
|---|---|---|
| 12 | 1A(1) + 3W(1) | 15.80 iter/s |
| 13 | 2A(2) + 4W(1) | 16.33 iter/s |
| 14 | 4A(4) + 2W(2) | 15.13 iter/s |

## Output

Raw results are saved to `verifico_results_32core.txt` in the repo root. Key metrics to extract from each test:

- `iterations.....................:` — throughput (iter/s)
- `login_latency..................:` — avg and p95 (the critical number)
- `token_latency..................:` — avg and p95
- `refresh_latency................:` — avg and p95
- `http_req_failed................:` — should be 0%

## What We're Looking For

1. **Does the k8s scaling curve flatten or keep climbing?** On the laptop it peaked at 16.33 iter/s. With 32 cores and no k6 contention, does adding more workers keep improving throughput?

2. **Where is the Autentico main process ceiling?** At some point, adding workers won't help because the 2-core Autentico can't push requests fast enough. That ceiling tells you when you need to scale Autentico itself (multiple instances + load balancer).

3. **Vertical vs horizontal crossover point.** At what core count does vertical scaling beat the best horizontal config? On the laptop it was 8 cores. With 32 cores available, the vertical numbers will be much higher.

4. **Login latency under load.** Users care about login speed, not throughput. The real question: with 50 concurrent users, can verifico keep login under 500ms?
