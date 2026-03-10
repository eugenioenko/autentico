import http from 'k6/http';
import { BASE_URL, CLIENT_ID, REDIRECT_URI, OAUTH_PATH, USERNAME, PASSWORD } from './lib/flow.js';

export const options = { vus: 1, iterations: 1 };

export default function () {
  const url = `${BASE_URL}${OAUTH_PATH}/authorize` +
    `?response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=openid+profile+email&state=debugstate` +
    `&code_challenge=abc123abc123abc123abc123abc123abc123abc123a&code_challenge_method=S256`;

  const authPage = http.get(url);
  console.log('authorize status:', authPage.status);

  // Print a snippet around the CSRF token
  const body = authPage.body;
  const csrfIdx = body.indexOf('csrf');
  if (csrfIdx >= 0) {
    console.log('csrf snippet:', body.substring(csrfIdx - 20, csrfIdx + 120));
  } else {
    console.log('csrf not found in body');
    console.log('body start:', body.substring(0, 300));
  }

  // Try the regex
  const match = body.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
  console.log('csrf regex match:', match ? match[1].substring(0, 20) + '...' : 'NO MATCH');

  if (!match) return;

  // Attempt login and print the response
  const loginResp = http.post(
    `${BASE_URL}${OAUTH_PATH}/login`,
    {
      'gorilla.csrf.Token': match[1],
      username: USERNAME,
      password: PASSWORD,
      state: 'debugstate',
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      scope: 'openid profile email',
      nonce: '',
      code_challenge: 'abc123abc123abc123abc123abc123abc123abc123a',
      code_challenge_method: 'S256',
    },
    { redirects: 0, headers: { Referer: `${BASE_URL}${OAUTH_PATH}/authorize`, Origin: BASE_URL } }
  );

  console.log('login status:', loginResp.status);
  console.log('login Location:', loginResp.headers['Location'] || 'none');
  console.log('login body:', loginResp.body.substring(0, 300));
}
