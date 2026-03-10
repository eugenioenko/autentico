/**
 * Smoke test — 1 VU, 30 seconds.
 * Verifies the full auth flow works at all before heavier tests.
 * Run: make stress-smoke
 */

import { sleep } from 'k6';
import { authFlow } from './lib/flow.js';

export const options = {
  vus:      1,
  duration: '30s',
  thresholds: {
    http_req_failed:   ['rate<0.01'],
    flow_success_rate: ['rate>0.99'],
    flow_errors:       ['count<2'],
    login_latency:     ['p(95)<1000'],
    token_latency:     ['p(95)<500'],
  },
};

export default function () {
  authFlow();
  sleep(1);
}
