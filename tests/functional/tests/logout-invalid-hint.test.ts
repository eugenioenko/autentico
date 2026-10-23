import { beforeAll, it, expect } from 'vitest';
import { generateKeyPairSync, sign, createHmac } from 'node:crypto';
import { join } from 'node:path';
import { OAUTH_URL, getAdminToken, postJSON } from '../helpers';
import { startServer, stopServer } from '../server-manager';

const own = generateKeyPairSync('rsa', { modulusLength: 2048 });
const foreign = generateKeyPairSync('rsa', { modulusLength: 2048 });
const client_id = 'invalid-hint-logout';
const callback = 'https://client.example/signed-out';
const payload = Buffer.from(JSON.stringify({ sub: 'user', aud: client_id, azp: client_id, exp: 1 })).toString('base64url');
function signedHint(alg: string, signature: (input: string) => string): string {
  const input = `${Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url')}.${payload}`;
  return `${input}.${signature(input)}`;
}

beforeAll(async () => {
  await stopServer();
  const pem = own.privateKey.export({ type: 'pkcs1', format: 'pem' });
  await startServer({ binary: join(import.meta.dirname, '../../../autentico'), args: ['start'],
    env: { AUTENTICO_PRIVATE_KEY: Buffer.from(pem).toString('base64') } });
  expect((await postJSON(`${OAUTH_URL}/register`, { client_id, client_name: client_id,
    redirect_uris: ['https://client.example/callback'], post_logout_redirect_uris: [callback],
  }, await getAdminToken())).status).toBe(201);
});

it('blocks invalid supplied hints on GET/POST, while accepting expired signed hints and optional omission', async () => {
  const cases = [
    ['malformed', 'garbage'],
    ['foreign', signedHint('RS256', input => sign('RSA-SHA256', Buffer.from(input), foreign.privateKey).toString('base64url'))],
    ['unsigned', signedHint('none', () => '')],
    ['hmac', signedHint('HS256', input => createHmac('sha256', own.publicKey.export({ type: 'spki', format: 'pem' })).update(input).digest('base64url'))],
    ['expired', signedHint('RS256', input => sign('RSA-SHA256', Buffer.from(input), own.privateKey).toString('base64url'))],
    ['absent', ''],
  ];
  for (const method of ['GET', 'POST']) {
    for (const includeClient of [false, true]) {
      for (const [name, hint] of cases) {
        const params = new URLSearchParams({ post_logout_redirect_uri: callback, state: 'opaque state' });
        if (includeClient) params.set('client_id', client_id);
        if (hint) params.set('id_token_hint', hint);
        const response = await fetch(`${OAUTH_URL}/logout${method === 'GET' ? `?${params}` : ''}`, {
          method, redirect: 'manual', headers: method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {},
          body: method === 'POST' ? params : undefined,
        });
        const redirects = name === 'expired' || name === 'absent' && includeClient;
        expect(response.status, `${method}/${name}/${includeClient}`).toBe(redirects ? 302 : 200);
        expect(response.headers.get('location')).toBe(redirects ? `${callback}?state=opaque+state` : null);
      }
    }
  }
});

it('does not redirect raw malformed query or form encoding', async () => {
 for (const method of ['GET','POST']) {
  for (const raw of [
   `id_token_hint=%ZZ&client_id=${client_id}&post_logout_redirect_uri=${encodeURIComponent(callback)}`,
   `state=%ZZ&client_id=${client_id}&post_logout_redirect_uri=${encodeURIComponent(callback)}`,
  ]) {
   const response=await fetch(`${OAUTH_URL}/logout${method === 'GET' ? `?${raw}` : ''}`,{method,redirect:'manual',headers:method === 'POST' ? {'Content-Type':'application/x-www-form-urlencoded'} : {},body:method === 'POST' ? raw : undefined});
   expect(response.status).toBe(200);expect(response.headers.get('location')).toBe(null);
  }
 }
});
