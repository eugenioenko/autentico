import { afterAll, beforeAll, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { BASE_URL, ADMIN_CLIENT_ID, ADMIN_REDIRECT_URI, getAdminToken, postJSON } from '../helpers';

let trap: Server;
let port: number;
let requests = 0;
let admin: string;
beforeAll(async () => {
  admin = await getAdminToken();
  trap = createServer((req, res) => {
    requests++;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const issuer = `http://${req.headers.host}`;
    res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` }));
  });
  await new Promise<void>(resolve => trap.listen(0, '127.0.0.1', resolve));
  port = (trap.address() as AddressInfo).port;
});
afterAll(async () => { await new Promise<void>(resolve => trap.close(() => resolve())); });

for (const host of ['127.0.0.1', 'localhost', '[::ffff:127.0.0.1]']) {
  it(`blocks initial discovery to ${host} through the production binary`, async () => {
    const id = `ssrf-${host.replace(/[^a-z0-9]/g, '-')}`;
    expect((await postJSON(`${BASE_URL}/admin/api/federation`, { id, name: 'Private fixture', issuer: `http://${host}:${port}`, client_id: 'upstream', client_secret: 'secret', enabled: true }, admin)).status).toBe(201);
    const params = new URLSearchParams({ client_id: ADMIN_CLIENT_ID, redirect_uri: ADMIN_REDIRECT_URI, scope: 'openid profile email', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' });
    const response = await fetch(`${BASE_URL}/oauth2/federation/${id}?${params}`, { redirect: 'manual' });
    expect(response.status).toBe(502);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(requests).toBe(0);
  });
}
