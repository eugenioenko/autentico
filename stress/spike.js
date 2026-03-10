/**
 * Spike test — ramps from 0 to 100 VUs and back.
 * Reveals how the server handles sudden bursts (e.g. after a deployment or viral moment).
 * SQLite single-writer contention will show up here first.
 * Run: make stress-spike
 */

import { sleep } from 'k6';
import { authFlow } from './lib/flow.js';

export const options = {
  scenarios: {
    spike: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10  }, // warm up
        { duration: '30s', target: 100 }, // spike
        { duration: '1m',  target: 100 }, // sustain
        { duration: '30s', target: 10  }, // recover
        { duration: '30s', target: 0   }, // cool down
      ],
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.05'],   // allow up to 5% errors during spike
    flow_success_rate: ['rate>0.90'],
    token_latency:     ['p(95)<2000'],  // more lenient under spike conditions
    login_latency:     ['p(95)<3000'],
  },
};

export default function () {
  authFlow();
  sleep(0.5);
}
