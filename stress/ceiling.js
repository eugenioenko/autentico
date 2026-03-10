/**
 * Ceiling test — ramps from 0 to 500 VUs to find the breaking point.
 * Thresholds are intentionally lenient; the goal is to observe where errors
 * first appear and where latency becomes user-unacceptable (>3s login p95).
 * Run: make stress-ceiling
 */

import { sleep } from 'k6';
import { authFlow } from './lib/flow.js';

export const options = {
  scenarios: {
    ceiling: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 50  }, // warm up
        { duration: '30s', target: 100 }, // known-good zone
        { duration: '30s', target: 200 }, // push
        { duration: '30s', target: 300 }, // push harder
        { duration: '30s', target: 500 }, // ceiling probe
        { duration: '1m',  target: 500 }, // sustain at ceiling
        { duration: '30s', target: 0   }, // cool down
      ],
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.10'],   // trip at 10% errors
    flow_success_rate: ['rate>0.85'],   // trip at 15% flow failures
    login_latency:     ['p(95)<10000'], // trip at 10s — just to catch total collapse
  },
};

export default function () {
  authFlow();
  sleep(0.5);
}
