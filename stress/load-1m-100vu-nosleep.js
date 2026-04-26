/**
 * Load test — 100 VUs for 1 minute, no sleep between iterations.
 * Back-to-back requests to find the actual throughput ceiling.
 */

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
    authorize_latency: ['p(95)<4000',  'p(99)<8000'],
    login_latency:     ['p(95)<8000',  'p(99)<16000'],
    token_latency:     ['p(95)<4000',  'p(99)<8000'],
    introspect_latency:['p(95)<4000',  'p(99)<8000'],
    refresh_latency:   ['p(95)<4000',  'p(99)<8000'],
  },
};

export default function () {
  authFlow();
}
