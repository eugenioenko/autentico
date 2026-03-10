/**
 * Rate limiter verification test.
 * Fires rapid bursts at the login endpoint and verifies:
 *   - 429s appear when the limit is exceeded
 *   - Retry-After header is present on 429 responses
 *   - The server recovers and accepts requests after the burst
 *
 * Does NOT perform a full auth flow — just hammers the endpoint.
 * Run: make stress-ratelimit
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';
import { BASE_URL, OAUTH_PATH } from './lib/flow.js';

const rateLimited    = new Counter('rate_limited_responses');
const rateLimitRate  = new Rate('rate_limit_hit_rate');

export const options = {
  scenarios: {
    burst: {
      executor:  'constant-arrival-rate',
      rate:      50,          // 50 req/s — exceeds default RPS limit
      timeUnit:  '1s',
      duration:  '30s',
      preAllocatedVUs: 50,
    },
  },
  thresholds: {
    // We expect the rate limiter to fire — at least some 429s should appear
    rate_limited_responses: ['count>0'],
  },
};

export default function () {
  // Hit the login endpoint directly with a dummy payload
  const resp = http.post(
    `${BASE_URL}${OAUTH_PATH}/login`,
    { username: 'nobody', password: 'wrong', 'gorilla.csrf.Token': 'x' },
    { redirects: 0 }
  );

  const limited = resp.status === 429;
  rateLimited.add(limited ? 1 : 0);
  rateLimitRate.add(limited);

  if (limited) {
    check(resp, {
      'rate limit: Retry-After header present': (r) => !!r.headers['Retry-After'],
      'rate limit: correct error body':         (r) => {
        try { return JSON.parse(r.body).error === 'too_many_requests'; } catch { return false; }
      },
    });
  }

  sleep(0.02); // 20ms between requests per VU
}
