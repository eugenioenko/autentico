import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { ADMIN, API, PASSWORD, dataset, formFields, localURL, seed, totp } from './seed.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

test('sample identities are deterministic and unique, with varied memberships and client types', () => {
  const data = dataset();
  assert.deepEqual(data, dataset());
  assert.equal(data.users.length, 100);
  assert.equal(new Set(data.users.map((u) => u.username)).size, 100);
  assert.equal(new Set(data.users.map((u) => u.email)).size, 100);
  for (const user of data.users) {
    assert.ok(user.email.endsWith('@acme.test'));
    assert.ok(user.groups.every((name) => data.groups.some((g) => g.name === name)));
  }
  assert.ok(data.clients.some((c) => c.client_type === 'public'));
  assert.ok(data.clients.some((c) => c.grant_types.includes('client_credentials')));
});

test('rejects non-local targets before making any requests', async () => {
  for (const url of ['https://auth.example.com', 'file:///tmp/db', 'http://localhost/path', 'http://admin:pw@localhost']) {
    await assert.rejects(seed(url), /loopback origin/);
  }
  assert.equal(localURL('http://[::1]:9999'), 'http://[::1]:9999');
});

test('reads hidden form inputs, decodes HTML and rejects missing CSRF protection', () => {
  assert.deepEqual(formFields('<input type="hidden" name="gorilla.csrf.Token" value="a&#43;b">' +
    '<input value="a&amp;b&quot;c" name="authorize_sig" type="hidden"><input name="password" type="password">'),
  { 'gorilla.csrf.Token': 'a+b', authorize_sig: 'a&b"c' });
  assert.throws(() => formFields('<html>Login unavailable</html>'), /CSRF/);
});

test('generates TOTP enrollment codes using the RFC 6238 SHA-1 test vector', () => {
  assert.equal(totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000), '287082');
});

test('seeds a fresh real server and reuses named records on a second run', { timeout: 120000 }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'autentico-seed-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = join(dir, 'autentico');
  execFileSync('go', ['build', '-o', binary, 'main.go'], { cwd: root, stdio: 'pipe' });
  const listener = createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const baseURL = `http://localhost:${listener.address().port}`;
  await new Promise((resolve) => listener.close(resolve));
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('AUTENTICO_')));
  execFileSync(binary, ['init', '--dev', '--url', baseURL], { cwd: dir, env, stdio: 'pipe' });
  const originalEnv = readFileSync(join(dir, '.env'));
  const server = spawn(binary, ['start'], { cwd: dir, env: { ...env,
    AUTENTICO_RATE_LIMIT_RPS: '0', AUTENTICO_RATE_LIMIT_RPM: '0',
    AUTENTICO_ANTI_TIMING_MIN_MS: '0', AUTENTICO_ANTI_TIMING_MAX_MS: '0',
  }, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  server.stdout.on('data', (chunk) => { logs += chunk; });
  server.stderr.on('data', (chunk) => { logs += chunk; });
  t.after(async () => {
    if (server.exitCode === null) {
      const stopped = once(server, 'exit');
      server.kill('SIGTERM');
      await stopped;
    }
  });
  const deadline = Date.now() + 15000;
  while (true) {
    try {
      if ((await fetch(`${baseURL}/healthz`)).ok) break;
    } catch { /* startup */ }
    assert.ok(server.exitCode === null && Date.now() < deadline, logs);
    await delay(50);
  }

  const { totals, adminToken } = await seed(baseURL, () => {});
  t.diagnostic(JSON.stringify(totals));
  assert.equal(totals.users, 101);
  assert.equal(totals.groups, 12);
  assert.equal(totals.clients, 38); // 24 sample clients + 12 ForwardAuth clients + 2 built-ins.
  assert.equal(totals.federation, 6);
  assert.equal(totals['protected-apps'], 12);
  assert.equal(totals['deletion-requests'], 8);
  assert.ok(totals.sessions >= 41);
  assert.ok(totals['idp-sessions'] >= 41);
  assert.ok(totals.tokens >= 45);
  assert.ok(totals['audit-logs'] > 500);
  const api = new API(baseURL);
  await assert.rejects(api.json('/admin/api/users'), /HTTP 401/);
  const users = await api.list('/admin/api/users', adminToken);
  assert.equal(users.filter((u) => u.totp_verified).length, 8);
  const alex = users.find((u) => u.username === dataset().users[0].username);
  assert.equal(alex.given_name, 'Alex');
  const claims = await api.json(`/admin/api/users/${alex.id}/claims`, { token: adminToken });
  assert.ok(claims.some((c) => c.name === 'employee_id' && c.value === 'ACME-0001'));
  const groups = await api.list('/admin/api/groups', adminToken);
  assert.equal(groups.find((g) => g.name === 'all-hands').member_count, 100);
  const providers = await api.list('/admin/api/federation', adminToken);
  assert.ok(providers.every((p) => !p.enabled));
  const tokens = await api.list('/admin/api/tokens', adminToken);
  assert.ok(tokens.some((token) => token.grant_type === 'client_credentials'));
  assert.ok(tokens.some((token) => token.status === 'revoked'));
  const clients = await api.list('/admin/api/clients', adminToken);
  assert.equal(clients.filter((c) => !c.is_active).length, 3);
  const settings = await api.json('/admin/api/settings', { token: adminToken });
  assert.equal(settings.cors_allowed_origins.split(',').length, 15);
  assert.equal(ADMIN.password, PASSWORD);

  const rerun = await seed(baseURL, () => {});
  for (const name of ['users', 'groups', 'clients', 'federation', 'protected-apps', 'deletion-requests']) {
    assert.equal(rerun.totals[name], totals[name], `duplicate ${name}`);
  }
  assert.equal(rerun.totals.sessions, totals.sessions + 1); // Only the seeder's new admin login.
  assert.deepEqual(readFileSync(join(dir, '.env')), originalEnv);
});
