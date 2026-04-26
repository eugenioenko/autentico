import { authFlow } from './lib/flow.js';

export const options = {
  scenarios: {
    steady: {
      executor:  'constant-vus',
      vus:       200,
      duration:  '30s',
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.01'],
    flow_success_rate: ['rate>0.95'],
  },
};

export default function () {
  authFlow();
}
