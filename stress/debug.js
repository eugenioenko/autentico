import http from 'k6/http';
import { BASE_URL, CLIENT_ID, REDIRECT_URI, OAUTH_PATH, USERNAME, PASSWORD } from './lib/flow.js';
import crypto from 'k6/crypto';

export const options = { vus: 1, iterations: 1 };

function extractFormValue(body, name) {
  const match = body.match(new RegExp(`name="${name}"\\s+value="([^"]*)"`));
  return match ? match[1] : '';
}

export default function () {
  const verifierBytes = crypto.randomBytes(32);
  const verifier = crypto.hexEncode(verifierBytes).slice(0, 43);
  const challenge = crypto.sha256(verifier, 'base64rawurl');

  const url = `${BASE_URL}${OAUTH_PATH}/authorize` +
    `?response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=openid+profile+email&state=debugstate` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;

  const authPage = http.get(url);
  console.log('authorize status:', authPage.status);

  const body = authPage.body;
  const csrfMatch = body.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
  console.log('csrf regex match:', csrfMatch ? csrfMatch[1].substring(0, 20) + '...' : 'NO MATCH');

  if (!csrfMatch) return;

  const sig = extractFormValue(body, 'authorize_sig');
  const state = extractFormValue(body, 'state');
  const scope = extractFormValue(body, 'scope');
  const nonce = extractFormValue(body, 'nonce');
  const cc = extractFormValue(body, 'code_challenge');
  const ccm = extractFormValue(body, 'code_challenge_method');
  const rid = extractFormValue(body, 'redirect_uri');
  const cid = extractFormValue(body, 'client_id');

  console.log('authorize_sig:', sig);
  console.log('state:', state, 'scope:', scope, 'nonce:', JSON.stringify(nonce));
  console.log('code_challenge:', cc);
  console.log('code_challenge_method:', ccm);
  console.log('redirect_uri:', rid);
  console.log('client_id:', cid);

  const formData = {
    'gorilla.csrf.Token': csrfMatch[1],
    username: USERNAME,
    password: PASSWORD,
    state: state,
    redirect_uri: rid,
    client_id: cid,
    scope: scope,
    nonce: nonce,
    code_challenge: cc,
    code_challenge_method: ccm,
    authorize_sig: sig,
  };

  const loginResp = http.post(
    `${BASE_URL}${OAUTH_PATH}/login`,
    formData,
    { redirects: 0, headers: { Referer: `${BASE_URL}${OAUTH_PATH}/authorize`, Origin: BASE_URL } }
  );

  console.log('login status:', loginResp.status);
  console.log('login Location:', loginResp.headers['Location'] || 'none');
  console.log('login body:', loginResp.body.substring(0, 300));
}
