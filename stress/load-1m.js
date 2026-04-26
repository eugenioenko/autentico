/**
 * Load test — steady 20 VUs for 1 minute.
 * Short run for quick benchmarking.
 */

import { sleep } from 'k6';
import { authFlow } from './lib/flow.js';

export const options = {
  scenarios: {
    steady: {
      executor:  'constant-vus',
      vus:       20,
      duration:  '1m',
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.01'],
    flow_success_rate: ['rate>0.95'],
    authorize_latency: ['p(95)<500',  'p(99)<1000'],
    login_latency:     ['p(95)<800',  'p(99)<1500'],
    token_latency:     ['p(95)<400',  'p(99)<800'],
    introspect_latency:['p(95)<300',  'p(99)<600'],
    refresh_latency:   ['p(95)<400',  'p(99)<800'],
  },
};

export default function () {
  authFlow();
  sleep(1);
}
