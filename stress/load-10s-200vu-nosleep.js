import { authFlow } from './lib/flow.js';

export const options = {
  scenarios: {
    steady: {
      executor:  'constant-vus',
      vus:       200,
      duration:  '10s',
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.05'],
    flow_success_rate: ['rate>0.90'],
  },
};

export default function () {
  authFlow();
}
