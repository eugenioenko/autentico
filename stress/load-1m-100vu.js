/**
 * Load test — steady 100 VUs for 1 minute.
 * High concurrency for verifico benchmarking.
 */

import { sleep } from 'k6';
import { authFlow } from './lib/flow.js';

export const options = {
  scenarios: {
    steady: {
      executor:  'constant-vus',
      vus:       100,
      duration:  '1m',
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.01'],
    flow_success_rate: ['rate>0.95'],
    authorize_latency: ['p(95)<2000',  'p(99)<4000'],
    login_latency:     ['p(95)<4000',  'p(99)<8000'],
    token_latency:     ['p(95)<2000',  'p(99)<4000'],
    introspect_latency:['p(95)<2000',  'p(99)<4000'],
    refresh_latency:   ['p(95)<2000',  'p(99)<4000'],
  },
};

export default function () {
  authFlow();
  sleep(1);
}
