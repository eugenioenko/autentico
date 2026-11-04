#!/usr/bin/env node
// Local development data, created through the same APIs as the UIs.
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const PASSWORD = 'Password123!';
export const ADMIN = { username: 'admin', password: PASSWORD, email: 'admin@acme.test' };

const firstNames = ['Alex', 'Amara', 'Ben', 'Chloe', 'Daniel', 'Elena', 'Fatima', 'Gabriel', 'Hana', 'Isaac',
  'Jade', 'Kai', 'Leila', 'Luca', 'Maya', 'Noah', 'Olivia', 'Priya', 'Rafael', 'Sofia'];
const lastNames = ['Anderson', 'Bennett', 'Chen', 'Diaz', 'Evans', 'Garcia', 'Hassan', 'Ito', 'Johnson', 'Kim',
  'Lopez', 'Martin', 'Nguyen', 'Okafor', 'Patel', 'Rivera', 'Singh', 'Taylor', 'Wilson', 'Young'];
const departments = ['Engineering', 'Design', 'Product', 'Marketing', 'Sales', 'Support', 'Finance', 'People'];
const appNames = ['Dashboard', 'Customer Portal', 'Analytics', 'Documentation', 'Billing', 'Support Desk',
  'Project Tracker', 'Knowledge Base', 'Status Page', 'Inventory', 'Calendar', 'Reports',
  'Partner Portal', 'Learning Hub', 'Expense Manager', 'Asset Library', 'Mobile App', 'Developer Console',
  'Build Pipeline', 'Nightly Sync', 'Report Worker', 'Metrics Collector', 'Office CLI', 'TV Dashboard'];

export function dataset() {
  const groups = [...departments, 'Leadership', 'Contractors', 'Beta Testers', 'All Hands'].map((name) => ({
    name: name.toLowerCase().replaceAll(' ', '-'), description: `${name} team at Acme`,
  }));
  const users = Array.from({ length: 100 }, (_, i) => {
    const first = firstNames[i % firstNames.length];
    const last = lastNames[(i * 7 + Math.floor(i / firstNames.length)) % lastNames.length];
    const username = `${first}.${last}`.toLowerCase();
    return {
      username, password: PASSWORD, email: `${username}@acme.test`, role: i < 4 ? 'admin' : 'user',
      profile: { given_name: first, family_name: last, is_email_verified: i % 7 !== 0,
        locale: ['en-US', 'en-GB', 'es-ES', 'fr-FR'][i % 4],
        zoneinfo: ['America/Los_Angeles', 'Europe/London', 'Asia/Tokyo'][i % 3],
        address_locality: ['San Francisco', 'London', 'Tokyo', 'Toronto'][i % 4],
      },
      groups: [...new Set([groups[i % 8].name, 'all-hands',
        ...(i % 4 === 0 ? ['beta-testers'] : []), ...(i < 8 ? ['leadership'] : []),
        ...(i % 9 === 0 ? ['contractors'] : []),
      ])],
    };
  });
  const clients = appNames.map((name, i) => {
    const service = i >= 18 && i < 22;
    const confidential = service || i % 3 === 1;
    const origin = `https://${name.toLowerCase().replaceAll(' ', '-')}.acme.test`;
    return {
      client_id: `seed-${name.toLowerCase().replaceAll(' ', '-')}`, client_name: `Acme ${name}`,
      client_type: confidential ? 'confidential' : 'public',
      ...(confidential ? { client_secret: 'local-dev-client-secret' } : {}),
      token_endpoint_auth_method: confidential ? 'client_secret_post' : 'none',
      redirect_uris: [`${origin}/callback`],
      grant_types: service ? ['client_credentials'] : ['authorization_code', 'refresh_token',
        ...(i >= 22 ? ['urn:ietf:params:oauth:grant-type:device_code'] : [])],
      response_types: ['code'],
      scopes: service ? `api:read api:write seed:${i}` : 'openid profile email offline_access groups custom_claims',
      description: `${name} — local development sample`, client_uri: origin,
      show_in_account: !service, consent_required: !service && i % 4 === 0,
    };
  });
  return { users, groups, clients };
}

export function localURL(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) ||
      !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Seed requires a loopback origin, e.g. http://localhost:9999');
  }
  return url.origin;
}

export function totp(secret, time = Date.now()) {
  const bits = [...secret.toUpperCase()].map((c) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c)
    .toString(2).padStart(5, '0')).join('');
  const key = Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(time / 30000)));
  const digest = createHmac('sha1', key).update(counter).digest();
  return String((digest.readUInt32BE(digest[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}

// Read server-rendered form inputs, including CSRF and signed continuations.
export function formFields(html) {
  const decode = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|amp|quot|apos|lt|gt);/gi, (_, entity) => {
    if (entity[0] === '#') return String.fromCodePoint(entity[1].toLowerCase() === 'x'
      ? parseInt(entity.slice(2), 16) : Number(entity.slice(1)));
    return { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>' }[entity.toLowerCase()];
  });
  const fields = {};
  for (const input of html.matchAll(/<input\b[^>]*>/gi)) {
    const attributes = Object.fromEntries([...input[0].matchAll(/([\w.-]+)="([^"]*)"/g)]
      .map(([, name, value]) => [name, decode(value)]));
    if (attributes.name && attributes.type === 'hidden') fields[attributes.name] = attributes.value ?? '';
  }
  if (!fields['gorilla.csrf.Token']) throw new Error('No CSRF token in the form; is this a fresh local instance?');
  return fields;
}

export class API {
  constructor(baseURL) { this.baseURL = localURL(baseURL); }

  async request(path, { method = 'GET', body, token, cookies, form = false, agent = 'Acme dev seed' } = {}) {
    const url = new URL(path, this.baseURL);
    if (url.origin !== this.baseURL) throw new Error('Unexpected redirect outside the local instance');
    const headers = { 'User-Agent': agent };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (cookies?.size) headers.Cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    if (body !== undefined) {
      headers['Content-Type'] = form ? 'application/x-www-form-urlencoded' : 'application/json';
      headers.Origin = this.baseURL;
      headers.Referer = `${this.baseURL}/`;
    }
    let response;
    try {
      response = await fetch(url, { method, headers, redirect: 'manual', signal: AbortSignal.timeout(15000),
        body: body === undefined ? undefined : form ? new URLSearchParams(body).toString() : JSON.stringify(body) });
    } catch (error) {
      throw new Error(`Cannot reach ${this.baseURL}; start it with make fresh first`, { cause: error });
    }
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0];
      const split = pair.indexOf('=');
      cookies?.set(pair.slice(0, split), pair.slice(split + 1));
    }
    if (response.status === 429) {
      throw new Error('Rate limited. Start the dev server with AUTENTICO_RATE_LIMIT_RPS=0 AUTENTICO_RATE_LIMIT_RPM=0');
    }
    if (response.status >= 400) {
      throw new Error(`${method} ${url.pathname}: HTTP ${response.status}: ${(await response.text()).slice(0, 300)}`);
    }
    return response;
  }

  async json(path, options) {
    const response = await this.request(path, options);
    const text = await response.text();
    if (!text) return null;
    const value = JSON.parse(text);
    return value.data ?? value;
  }

  async list(path, token) {
    const items = [];
    while (true) {
      const page = await this.json(`${path}?limit=100&offset=${items.length}`, { token });
      if (Array.isArray(page)) return page;
      if (!Array.isArray(page.items)) throw new Error(`Unexpected list response from ${path}`);
      items.push(...page.items);
      if (items.length >= page.total || page.items.length === 0) return items;
    }
  }

  async onboard() {
    const cookies = new Map();
    const page = await this.request('/onboard', { cookies });
    if (page.status === 302) return;
    const response = await this.request('/onboard', { method: 'POST', cookies, form: true,
      body: { ...formFields(await page.text()), ...ADMIN, confirm_password: PASSWORD } });
    if (response.status !== 302) throw new Error('Admin onboarding failed');
  }

  async login(username, client = { client_id: 'autentico-admin', redirect_uris: [`${this.baseURL}/admin/callback`] }, agent) {
    const cookies = new Map();
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(16).toString('hex');
    const authorize = new URL(`${this.baseURL}/oauth2/authorize`);
    authorize.search = new URLSearchParams({ client_id: client.client_id, redirect_uri: client.redirect_uris[0],
      response_type: 'code', scope: 'openid profile email offline_access', state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' });
    const page = await this.request(authorize, { cookies, agent });
    let response = await this.request('/oauth2/login', { method: 'POST', form: true, cookies, agent,
      body: { ...Object.fromEntries(authorize.searchParams), ...formFields(await page.text()), username, password: PASSWORD } });
    let location = new URL(response.headers.get('Location') ?? '/', this.baseURL);
    if (location.origin === this.baseURL && location.pathname === '/oauth2/consent') {
      const consent = await this.request(location, { cookies, agent });
      response = await this.request('/oauth2/consent', { method: 'POST', form: true, cookies, agent,
        body: { ...formFields(await consent.text()), action: 'allow' } });
      location = new URL(response.headers.get('Location') ?? '/', this.baseURL);
    }
    const callback = new URL(client.redirect_uris[0]);
    if (response.status !== 302 || location.origin !== callback.origin || location.pathname !== callback.pathname ||
        location.searchParams.get('state') !== state || !location.searchParams.get('code')) {
      throw new Error(`Login failed for ${username}; expected the seed password and password login without MFA`);
    }
    return this.json('/oauth2/token', { method: 'POST', form: true, agent, body: {
      grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: client.redirect_uris[0],
      code: location.searchParams.get('code'), code_verifier: verifier,
      ...(client.client_secret ? { client_secret: client.client_secret } : {}),
    } });
  }
}

export async function seed(baseURL = 'http://localhost:9999', log = console.log) {
  const api = new API(baseURL);
  await api.json('/healthz');
  await api.onboard();
  const adminToken = (await api.login(ADMIN.username)).access_token;
  const post = (path, body) => api.json(path, { method: 'POST', body, token: adminToken });
  const put = (path, body) => api.json(path, { method: 'PUT', body, token: adminToken });
  const data = dataset();
  const origins = appNames.slice(0, 15).map((name) => `https://${name.toLowerCase().replaceAll(' ', '-')}.acme.test`);
  const settings = await api.json('/admin/api/settings', { token: adminToken });
  await put('/admin/api/settings', { sso_enabled: 'true', allow_self_service_deletion: 'false',
    cors_allowed_origins: [...new Set([...(settings.cors_allowed_origins ?? '').split(',').filter(Boolean), ...origins])].join(',') });

  log('Seeding groups and group claims…');
  const groups = new Map((await api.list('/admin/api/groups', adminToken)).map((g) => [g.name, g]));
  for (const group of data.groups) {
    if (!groups.has(group.name)) groups.set(group.name, await post('/admin/api/groups', group));
    const path = `/admin/api/groups/${groups.get(group.name).id}`;
    await post(`${path}/claims`, { name: 'workspace', value: group.name });
    await post(`${path}/claims`, { name: 'environment', value: 'development' });
  }
  const members = new Map();
  for (const group of groups.values()) {
    members.set(group.name, new Set((await api.json(`/admin/api/groups/${group.id}/members`, { token: adminToken })).map((m) => m.user_id)));
  }

  log('Seeding 100 users, profiles, memberships and custom claims…');
  const users = new Map((await api.list('/admin/api/users', adminToken)).map((u) => [u.username, u]));
  for (const [i, user] of data.users.entries()) {
    let saved = users.get(user.username);
    if (!saved) {
      const { profile, groups: _groups, ...request } = user;
      saved = await post('/admin/api/users', request);
      await put(`/admin/api/users/${saved.id}`, profile);
      users.set(user.username, saved);
    }
    for (const name of user.groups) {
      if (!members.get(name).has(saved.id)) {
        await post(`/admin/api/groups/${groups.get(name).id}/members`, { user_id: saved.id });
        members.get(name).add(saved.id);
      }
    }
    for (const [name, value] of Object.entries({ employee_id: `ACME-${String(i + 1).padStart(4, '0')}`,
      department: departments[i % departments.length], plan: ['starter', 'team', 'enterprise'][i % 3] })) {
      await post(`/admin/api/users/${saved.id}/claims`, { name, value });
    }
  }

  log('Seeding OAuth clients, federation providers and protected apps…');
  const clients = new Map((await api.list('/admin/api/clients', adminToken)).map((c) => [c.client_id, c]));
  for (const client of data.clients) {
    if (!clients.has(client.client_id)) clients.set(client.client_id, await post('/admin/api/clients', client));
  }
  for (const client of data.clients.slice(-2)) await put(`/admin/api/clients/${client.client_id}`, { is_active: false });
  const providers = new Set((await api.list('/admin/api/federation', adminToken)).map((p) => p.id));
  for (const [i, name] of ['Workforce', 'Partners', 'Contractors', 'Legacy SSO', 'Sandbox', 'Regional Office'].entries()) {
    const id = `seed-${name.toLowerCase().replaceAll(' ', '-')}`;
    if (!providers.has(id)) await post('/admin/api/federation', { id, name: `Acme ${name}`,
      issuer: `https://${id}.identity.test`, client_id: id, client_secret: 'local-dev-provider-secret',
      enabled: false, sort_order: i, claim_requirements: [{ claim: 'email_verified', match: 'equals', value: true }] });
  }
  const apps = new Set((await api.list('/admin/api/protected-apps', adminToken)).map((a) => a.origin));
  for (const [i, name] of appNames.slice(0, 12).entries()) {
    if (!apps.has(origins[i])) await post('/admin/api/protected-apps', { name: `Acme ${name}`, origin: origins[i],
      allowed_return_paths: i % 2 ? ['/app', '/settings'] : ['/'], session_ttl: i % 2 ? '8h' : '24h', is_active: i !== 11 });
  }

  log('Creating real sign-ins, sessions, tokens, consent grants and deletion requests…');
  const account = { client_id: 'autentico-account', redirect_uris: [`${api.baseURL}/account/callback`] };
  const deletionUsers = new Set((await api.list('/admin/api/deletion-requests', adminToken)).map((r) => r.user_id));
  const sessions = await api.list('/admin/api/sessions', adminToken);
  const signedIn = new Set(sessions.map((s) => `${s.user_id}:${s.user_agent}`));
  const agents = ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/130.0 AcmeSeed',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/132.0 AcmeSeed',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0 Safari/604.1 AcmeSeed'];
  for (let i = 0; i < 40; i++) {
    const user = data.users[i];
    const id = users.get(user.username).id;
    // First eight are account sessions; the others exercise a mix of app clients.
    const client = i < 8 ? account : data.clients[i % 16];
    const agent = `${agents[i % agents.length]}-${i}`;
    if (signedIn.has(`${id}:${agent}`) && (i >= 8 || deletionUsers.has(id))) continue;
    const tokens = await api.login(user.username, client, agent);
    if (i < 8 && !deletionUsers.has(id)) {
      await api.json('/account/api/deletion-request', { method: 'POST', token: tokens.access_token,
        body: { reason: ['Leaving the company', 'Duplicate account', 'Moving to another team', 'Project completed'][i % 4] } });
    }
    if (i >= 36) {
      await api.json('/oauth2/revoke', { method: 'POST', form: true, body: {
        token: tokens.refresh_token, token_type_hint: 'refresh_token', client_id: client.client_id,
        ...(client.client_secret ? { client_secret: client.client_secret } : {}),
      } });
    }
  }
  const tokenScopes = new Set((await api.list('/admin/api/tokens', adminToken)).map((t) => t.scope));
  for (const client of data.clients.filter((c) => c.grant_types.includes('client_credentials'))) {
    const scope = `api:read ${client.scopes.split(' ').at(-1)}`;
    if (!tokenScopes.has(scope)) await api.json('/oauth2/token', { method: 'POST', form: true,
      body: { grant_type: 'client_credentials', client_id: client.client_id, client_secret: client.client_secret, scope } });
  }
  const freshSessions = await api.list('/admin/api/sessions', adminToken);
  for (const session of freshSessions.filter((s) => s.user_agent?.endsWith('AcmeSeed-39') && s.status === 'active')) {
    await api.json(`/admin/api/sessions/${session.id}`, { method: 'DELETE', token: adminToken });
  }

  log('Enrolling sample accounts in TOTP MFA…');
  for (const user of data.users.slice(60, 68)) {
    if (users.get(user.username).totp_verified) continue;
    const { access_token: token } = await api.login(user.username, account);
    const { secret } = await api.json('/account/api/mfa/totp/setup', { method: 'POST', token, body: { current_password: PASSWORD } });
    await api.json('/account/api/mfa/totp/verify', { method: 'POST', token, body: { code: totp(secret) } });
  }

  const totals = {};
  for (const entity of ['users', 'groups', 'clients', 'federation', 'protected-apps', 'sessions', 'idp-sessions', 'tokens', 'deletion-requests', 'audit-logs']) {
    totals[entity] = (await api.list(`/admin/api/${entity}`, adminToken)).length;
  }
  log(`Seed complete: ${Object.entries(totals).map(([name, count]) => `${count} ${name}`).join(', ')}.`);
  log(`Admin UI: ${api.baseURL}/admin/ — ${ADMIN.username} / ${PASSWORD}`);
  log(`Sample account: ${data.users[0].username} / ${PASSWORD} (all generated users share this dev password).`);
  log('Federation providers use placeholder .test URLs and are disabled.');
  return { totals, adminToken };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  seed(process.argv[2]).catch((error) => { console.error(`Seed failed: ${error.message}`); process.exitCode = 1; });
}
