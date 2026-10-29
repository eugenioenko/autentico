import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { generateTOTP } from '../../totp-helper';

type App = { id: string; name: string; origin: string; allowed_return_paths: string[]; session_ttl: string; is_active: boolean; client_id: string };
const fixture = JSON.parse(readFileSync(process.env.AUTENTICO_PROXY_FIXTURE!, 'utf8'));
const apps = fixture.apps as Record<string, App>;
const password = 'Password123!';
async function api(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST') {
  return fetch(fixture.admin + path, { method, headers: { Authorization: `Bearer ${fixture.token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
}
async function updateApp(a: App, changes: Partial<App> = {}) {
  const { name, origin, allowed_return_paths, session_ttl, is_active } = { ...a, ...changes };
  const response = await api(`/admin/api/protected-apps/${a.id}`, { name, origin, allowed_return_paths, session_ttl, is_active }, 'PUT');
  expect(response.status, await response.text()).toBe(200);
}
async function settings(body: Record<string, string>) {
  const response = await api('/admin/api/settings', body, 'PUT');
  expect(response.status, await response.text()).toBe(204);
}
async function control(path: string) {
  const response = await fetch(fixture.control + path, { method: 'POST', headers: { Authorization: `Bearer ${fixture.controlKey}` } });
  expect(response.status).toBe(200); return response.json();
}
async function submitLogin(page: Page, username = 'proxy-user') {
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('button[type=submit]').click();
}
async function login(page: Page, a: App, target = '/reports?month=10&label=a%26b') {
  await page.goto(a.origin + target);
  await expect(page.locator('#username')).toBeVisible();
  await submitLogin(page);
  await page.waitForURL(a.origin + target);
  const result = JSON.parse(await page.locator('body').innerText());
  const headers = Object.fromEntries(Object.entries(result.headers).map(([k, v]) => [k.toLowerCase(), v]));
  expect(String(headers.cookie ?? '')).not.toContain('autentico_fa_');
  expect(String(headers.cookie ?? '')).not.toContain('autentico_idp_session');
  return result;
}
async function shell(page: Page, a: App) {
  const response = await page.goto(`${a.origin}/_autentico/${a.id}/callback`);
  expect(response!.status()).toBe(400);
}
async function appFetch(page: Page, path: string, method = 'GET', accept = 'application/json', body?: string) {
  return page.evaluate(async ({ path, method, accept, body }) => {
    const response = await fetch(path, { method, headers: { Accept: accept }, body, redirect: 'manual' });
    return { status: response.status, body: await response.text(), headers: Object.fromEntries(response.headers) };
  }, { path, method, accept, body });
}
async function appCookie(context: BrowserContext, a: App) {
  const cookie = (await context.cookies(a.origin)).find(c => c.name === `__Host-autentico_fa_${a.id}`);
  expect(cookie).toBeTruthy(); return cookie!;
}

// Pause only the final login redirect for attack tests. The form is submitted
// through the real TLS proxy with a test-only DNS lookup; no handler is mocked.
async function captureLogin(page: Page, app: App) {
  let callback = '';
  await page.route('**/oauth2/login', async route => {
    const request = route.request();
    const headers = await request.allHeaders();
    callback = await new Promise<string>((resolve, reject) => {
      const req = httpsRequest(request.url(), {
        method: request.method(), headers, rejectUnauthorized: false, family: 4,
        lookup: (_host, _options, done) => done(null, '127.0.0.1', 4),
      }, response => {
        response.resume();
        response.on('end', () => response.headers.location ? resolve(response.headers.location) : reject(new Error(`Login returned ${response.statusCode}`)));
      });
      req.on('error', reject); req.end(request.postDataBuffer());
    });
    await route.fulfill({ status: 200, body: 'Paused before callback redemption' });
  });
  try {
    await page.goto(app.origin + '/reports'); await submitLogin(page);
    await expect.poll(() => callback).not.toBe('');
    return callback;
  } finally { await page.unroute('**/oauth2/login'); }
}

test.beforeEach(async () => {
  await settings({ require_mfa: 'false', require_email_verification: 'false', sso_enabled: 'true', sso_session_max_age: '24h', sso_session_idle_timeout: '4h', authorization_code_expiration: '5m' });
  for (const app of Object.values(apps)) await updateApp(app);
  const response = await api(`/admin/api/users/${fixture.user.id}/reactivate`, {});
  expect([204, 404]).toContain(response.status);
  expect((await api(`/admin/api/users/${fixture.user.id}`, { is_email_verified: true }, 'PUT')).status).toBe(200);
});

for (const [proxy, app] of Object.entries(apps)) {
  test.describe(proxy, () => {
    test('complete browser login, query restoration, isolated cookies, identity replacement and POST forwarding', async ({ page, context }) => {
      await context.addCookies([{ name: 'app-preference', value: 'dark', url: app.origin }]);
      await context.setExtraHTTPHeaders({ 'X-Auth-User': 'forged', 'X-Auth-Email': 'forged@evil.test', 'X-Auth-Groups': 'admins', 'X-Forwarded-Host': 'evil.test', 'X-Forwarded-Proto': 'http', 'X-Forwarded-Uri': '//evil.test', 'X-Forwarded-Method': 'DELETE' });
      const result = await login(page, app);
      expect(result.path).toBe('/reports?month=10&label=a%26b');
      
      const headers = Object.fromEntries(Object.entries(result.headers).map(([k, v]) => [k.toLowerCase(), v]));
      expect(headers['x-auth-user']).toBe(fixture.user.id); expect(headers['x-auth-email']).toBe('proxy@test.com'); expect(headers['x-auth-groups']).toBeUndefined();
      expect(headers.cookie).toBe('app-preference=dark');
      const cookie = await appCookie(context, app);
      expect(cookie.secure).toBe(true); expect(cookie.httpOnly).toBe(true); expect(cookie.sameSite).toBe('Lax'); expect(cookie.domain).toBe(new URL(app.origin).hostname);
      const central = (await context.cookies(fixture.auth)).find(c => c.name === 'autentico_idp_session');
      expect(central).toBeTruthy(); expect(central!.value).not.toBe(cookie.value);
      expect((await context.cookies(app.origin)).some(c => c.name === 'autentico_idp_session')).toBe(false);
      const posted = await appFetch(page, '/submit?x=1', 'POST', 'application/json', 'untouched-body');
      expect(posted.status).toBe(200); expect(JSON.parse(posted.body).body).toBe('untouched-body'); expect(JSON.parse(posted.body).method).toBe('POST');
      expect(page.url()).not.toContain('code=');
    });

    test('anonymous APIs, unsafe methods and forged identity cannot reach the backend', async ({ page }) => {
      await shell(page, app);
      const before = await control('/stats');
      for (const [method, accept] of [['GET', 'application/json'], ['POST', 'text/html'], ['HEAD', 'application/json']]) {
        const response = await appFetch(page, '/private', method, accept);
        expect(response.status).toBe(401);
      }
      expect((await control('/stats')).hits).toBe(before.hits);
    });

    test('unsafe return URLs and out-of-policy paths are rejected without a backend request', async ({ page }) => {
      const before = await control('/stats');
      for (const path of ['https://evil.test/', '//evil.test/', '/%2f%2fevil.test', '/reports/../secret', '/reports/%252e%252e/secret', '/_autentico/start', '/reports\\evil', '/reports#fragment', '/reports/..;/admin', '/reports/%2e%2e%3b/admin']) {
        const response = await page.goto(`${app.origin}/_autentico/${app.id}/start?return=${encodeURIComponent(path)}`);
        expect(response!.status(), path).toBe(400);
      }
      await updateApp(app, { allowed_return_paths: ['/reports'] });
      expect((await page.goto(app.origin + '/reports-evil'))!.status()).toBe(403);
      expect((await control('/stats')).hits).toBe(before.hits);
      await login(page, app);
      const authenticated = await control('/stats');
      for (const path of ['/reports/..;/admin', '/reports/%2e%2e%3b/admin', '/reports/a;parameter/admin']) {
        expect((await appFetch(page, path)).status, path).toBe(403);
      }
      expect((await control('/stats')).hits).toBe(authenticated.hits);
    });


    test('unverified email is never forwarded as trusted identity', async ({ page, context }) => {
      await context.setExtraHTTPHeaders({ 'X-Auth-Email': 'forged@evil.test' });
      await login(page, app);
      expect((await api(`/admin/api/users/${fixture.user.id}`, { is_email_verified: false }, 'PUT')).status).toBe(200);
      let result = await appFetch(page, '/reports'); expect(result.status).toBe(200);
      let headers = Object.fromEntries(Object.entries(JSON.parse(result.body).headers).map(([key, value]) => [key.toLowerCase(), value]));
      expect(headers['x-auth-user']).toBe(fixture.user.id); expect(headers['x-auth-email']).toBeUndefined();
      expect((await api(`/admin/api/users/${fixture.user.id}`, { is_email_verified: true }, 'PUT')).status).toBe(200);
      result = await appFetch(page, '/reports'); expect(result.status).toBe(200);
      headers = Object.fromEntries(Object.entries(JSON.parse(result.body).headers).map(([key, value]) => [key.toLowerCase(), value]));
      expect(headers['x-auth-email']).toBe('proxy@test.com');
    });

    test('six forced same-site image logins cannot lock the browser out', async ({ page, context }) => {
      await page.goto('https://evil.example.test:25443/');
      for (let i = 0; i < 6; i++) {
        const start = `${app.origin}/_autentico/${app.id}/start?return=${encodeURIComponent('/reports?pending=' + i)}`;
        await page.evaluate(url => new Promise<void>(resolve => {
          const image = new Image(); image.onload = image.onerror = () => resolve(); image.src = url; document.body.append(image);
        }), start);
      }
      const prefix = `__Host-autentico_fa_${app.id}_flow_`;
      const before = (await context.cookies(app.origin)).filter(cookie => cookie.name.startsWith(prefix));
      expect(before).toHaveLength(6);
      const destination = '/reports?pending=owner';
      await page.goto(`${app.origin}/_autentico/${app.id}/start?return=${encodeURIComponent(destination)}`);
      await expect(page.locator('#username')).toBeVisible();
      expect((await context.cookies(app.origin)).filter(cookie => cookie.name.startsWith(prefix))).toHaveLength(6);
      await submitLogin(page); await page.waitForURL(app.origin + destination);
      const backend = JSON.parse(await page.locator('body').innerText());
      expect(String(backend.headers.Cookie ?? backend.headers.cookie ?? '')).not.toContain('autentico_fa_');
      await appCookie(context, app);
    });

    test('long pending flows stay within the cookie budget and allow the next login', async ({ page, context }) => {
      await context.addCookies([{ name: 'app-preference', value: 'x'.repeat(512), url: app.origin }]);
      for (let i = 0; i < 6; i++) {
        const destination = '/reports?tab=' + i + '&query=' + 'x'.repeat(1000);
        await page.goto(`${app.origin}/_autentico/${app.id}/start?return=${encodeURIComponent(destination)}`);
        await expect(page.locator('#username')).toBeVisible();
        const flows = (await context.cookies(app.origin)).filter(cookie => cookie.name.startsWith(`__Host-autentico_fa_${app.id}_flow_`));
        expect(flows.length).toBeGreaterThan(0);
        expect(flows.length).toBeLessThan(6);
        expect(flows.reduce((size, cookie) => size + cookie.name.length + 1 + cookie.value.length + 2, 0)).toBeLessThanOrEqual(6 * 1024);
      }
      const oversized = await page.goto(`${app.origin}/_autentico/${app.id}/start?return=${encodeURIComponent('/reports?query=' + 'x'.repeat(3000))}`);
      expect(oversized!.status()).toBe(400);
      const destination = '/reports?owner=' + 'y'.repeat(1000);
      await page.goto(`${app.origin}/_autentico/${app.id}/start?return=${encodeURIComponent(destination)}`);
      await submitLogin(page); await page.waitForURL(app.origin + destination);
      const result = JSON.parse(await page.locator('body').innerText());
      expect(result.path).toBe(destination);
      expect(String(result.headers.Cookie ?? result.headers.cookie ?? '')).toContain('app-preference=');
      expect(String(result.headers.Cookie ?? result.headers.cookie ?? '')).not.toContain('autentico_fa_');
    });

    test('wrong browser, tampered state, wrong code and replay cannot complete login', async ({ page, browser }) => {
      const callback = await captureLogin(page, app);
      const other = await browser.newContext({ ignoreHTTPSErrors: true });
      try { expect((await (await other.newPage()).goto(callback))!.status()).toBe(400); } finally { await other.close(); }
      const tampered = new URL(callback); tampered.searchParams.set('state', 'a'.repeat(43));
      expect((await page.goto(tampered.toString()))!.status()).toBe(400);
      const wrongCode = new URL(callback); wrongCode.searchParams.set('code', 'a'.repeat(43));
      expect((await page.goto(wrongCode.toString()))!.status()).toBe(400);
      await page.goto(callback); await page.waitForURL(app.origin + '/reports');
      expect((await page.goto(callback))!.status()).toBe(400);
    });

    test('server-side expiry, app disable/re-enable and local logout reject retained credentials', async ({ page, context }) => {
      await updateApp(app, { session_ttl: '2s' });
      await login(page, app); const expired = await appCookie(context, app);
      await expect.poll(async () => (await appFetch(page, '/private')).status, { timeout: 6000 }).toBe(401);
      await context.addCookies([{ ...expired, expires: Date.now() / 1000 + 3600 }]);
      expect((await appFetch(page, '/private')).status).toBe(401);
      await updateApp(app); await context.clearCookies(); await login(page, app);
      const retained = await appCookie(context, app);
      await updateApp(app, { is_active: false }); expect((await appFetch(page, '/private')).status).toBe(403);
      await updateApp(app); expect((await appFetch(page, '/private')).status).toBe(401);
      await context.clearCookies(); await login(page, app);
      const current = await appCookie(context, app);
      expect((await appFetch(page, `/_autentico/${app.id}/logout`, 'POST')).status).toBe(204);
      await context.addCookies([current]); expect((await appFetch(page, '/private')).status).toBe(401);
      expect(current.value).not.toBe(retained.value);
    });

    test('central revocation, disabled accounts and changed MFA policy stop existing app access', async ({ page, context }) => {
      await login(page, app);
      expect((await api(`/admin/api/users/${fixture.user.id}/revoke-sessions`, {})).status).toBe(204);
      expect((await appFetch(page, '/private')).status).toBe(401);
      await context.clearCookies(); await login(page, app);
      expect((await api(`/admin/api/users/${fixture.user.id}/deactivate`, {})).status).toBe(204);
      expect((await appFetch(page, '/private')).status).toBe(401);
      expect((await api(`/admin/api/users/${fixture.user.id}/reactivate`, {})).status).toBe(204);
      await context.clearCookies(); await login(page, app);
      await settings({ require_mfa: 'true', mfa_method: 'totp' });
      expect((await appFetch(page, '/private')).status).toBe(401);
    });

    test('real MFA is required before any application session is issued', async ({ page, context }) => {
      const username = `mfa-${proxy}`;
      const created = await api('/admin/api/users', { username, password, email: `${username}@test.com` });
      expect(created.status).toBe(201);
      await settings({ require_mfa: 'true', mfa_method: 'totp' });
      await page.goto(app.origin + '/reports'); await submitLogin(page, username);
      await expect(page.locator('.auth-secret-key')).toBeVisible();
      expect((await context.cookies(app.origin)).some(c => c.name === `__Host-autentico_fa_${app.id}`)).toBe(false);
      const secret = (await page.locator('.auth-secret-key').innerText()).trim();
      await page.locator('#code').fill('000000'); await page.getByRole('button', { name: 'Verify & Enable', exact: true }).click();
      expect((await context.cookies(app.origin)).some(c => c.name === `__Host-autentico_fa_${app.id}`)).toBe(false);
      await page.locator('#code').fill(generateTOTP(secret)); await page.getByRole('button', { name: 'Verify & Enable', exact: true }).click();
      await page.waitForURL(app.origin + '/reports'); await appCookie(context, app);
    });

    test('auth-service outage denies access without forwarding the request', async ({ page }) => {
      await login(page, app);
      const before = await control('/stats'); await control('/stop-auth');
      try { expect((await appFetch(page, '/private')).status).toBeGreaterThanOrEqual(500); expect((await control('/stats')).hits).toBe(before.hits); }
      finally { await control('/start-auth'); }
      expect((await appFetch(page, '/private')).status).toBe(200);
    });
  });
}

test('SSO across app hosts keeps credentials isolated and survives a server restart', async ({ page, context }) => {
  await login(page, apps.caddy);
  const first = await appCookie(context, apps.caddy);
  await page.goto(apps.nginx.origin + '/reports?from=sso'); await page.waitForURL(apps.nginx.origin + '/reports?from=sso');
  const second = await appCookie(context, apps.nginx); expect(second.value).not.toBe(first.value);
  await context.addCookies([{ ...second, value: first.value }]);
  expect((await appFetch(page, '/private')).status).toBe(401);
  await context.addCookies([second]);
  await control('/stop-auth'); await control('/start-auth');
  expect((await appFetch(page, '/private')).status).toBe(200);
});

test('parallel tabs preserve separate login transactions and original destinations', async ({ page, context }) => {
  const app = apps.caddy;
  const second = await context.newPage();
  await page.goto(app.origin + '/first?tab=one'); await second.goto(app.origin + '/second?tab=two');
  await submitLogin(page); await page.waitForURL(app.origin + '/first?tab=one');
  await submitLogin(second); await second.waitForURL(app.origin + '/second?tab=two');
  expect((await appFetch(page, '/private')).status).toBe(200); await second.close();
});

test('pending callback survives restart but rejects an expired authorization code', async ({ page }) => {
  const app = apps.caddy;
  const callback = await captureLogin(page, app);
  await control('/stop-auth'); await control('/start-auth');
  await page.goto(callback); await page.waitForURL(app.origin + '/reports');
  await settings({ authorization_code_expiration: '1s' });
  await page.context().clearCookies();
  const expired = await captureLogin(page, app);
  // Wait for the configured real expiry; no database manipulation or fake clock.
  await new Promise(resolve => setTimeout(resolve, 1200));
  expect((await page.goto(expired))!.status()).toBe(400);
});

test('admin API rejects unauthenticated and invalid changes without mutating configuration', async () => {
  expect((await fetch(fixture.admin + '/admin/api/protected-apps')).status).toBe(401);
  const before = await (await api('/admin/api/protected-apps')).json();
  for (const origin of ['https://evil.test', 'http://app.example.test', 'https://app.example.test/path', fixture.auth]) {
    expect((await api('/admin/api/protected-apps', { name: 'bad', origin, allowed_return_paths: ['/'] })).status).toBe(400);
  }
  expect((await api(`/admin/api/protected-apps/${apps.caddy.id}`, { name: 'changed', origin: apps.nginx.origin, allowed_return_paths: ['/'] }, 'PUT')).status).toBe(400);
  expect(await (await api('/admin/api/protected-apps')).json()).toEqual(before);
});

test('untrusted network peers cannot forge original-request headers', async () => {
  const a = apps.caddy;
  const status = await new Promise<number>((resolve, reject) => {
    const req = httpRequest(fixture.admin + `/forward-auth/${a.id}/check`, { localAddress: '127.0.0.2', headers: { 'X-Forwarded-Host': new URL(a.origin).host, 'X-Forwarded-Proto': 'https', 'X-Forwarded-Uri': '/', 'X-Forwarded-Method': 'GET' } }, response => { response.resume(); resolve(response.statusCode!); });
    req.on('error', reject); req.end();
  });
  expect(status).toBe(403);
});

test('central browser logout revokes both app sessions while leaving their cookies harmless', async ({ page, context }) => {
  await login(page, apps.caddy);
  const first = await appCookie(context, apps.caddy);
  await page.goto(apps.nginx.origin + '/reports'); await page.waitForURL(apps.nginx.origin + '/reports');
  const second = await appCookie(context, apps.nginx);
  await page.goto(fixture.auth + '/oauth2/logout');
  expect((await context.cookies(fixture.auth)).some(c => c.name === 'autentico_idp_session')).toBe(false);
  for (const [app, cookie] of [[apps.caddy, first], [apps.nginx, second]] as const) {
    await context.addCookies([cookie]); await shell(page, app);
    expect((await appFetch(page, '/private')).status).toBe(401);
  }
});

test('central absolute/idle expiry and tightened paths apply to existing sessions', async ({ page, context }) => {
  const app = apps.caddy;
  for (const setting of ['sso_session_idle_timeout', 'sso_session_max_age']) {
    await settings({ sso_session_idle_timeout: '4h', sso_session_max_age: '24h' });
    await context.clearCookies(); await login(page, app);
    await settings({ [setting]: '2s' });
    await new Promise(resolve => setTimeout(resolve, 2200));
    expect((await appFetch(page, '/private')).status).toBe(401);
  }
  await settings({ sso_session_idle_timeout: '4h', sso_session_max_age: '24h' });
  await context.clearCookies(); await login(page, app);
  await updateApp(app, { allowed_return_paths: ['/reports'] });
  expect((await appFetch(page, '/reports')).status).toBe(200);
  expect((await appFetch(page, '/reports-other')).status).toBe(403);
});

test('SSO-disabled deployments still complete login but require reauthentication for another app', async ({ page }) => {
  await settings({ sso_enabled: 'false' });
  await login(page, apps.caddy);
  await page.goto(apps.nginx.origin + '/reports');
  await expect(page.locator('#username')).toBeVisible();
  await submitLogin(page); await page.waitForURL(apps.nginx.origin + '/reports');
});

test('forged app cookie, duplicate cookies, crossed callbacks and missing callback data are rejected', async ({ page, context }) => {
  const app = apps.caddy;
  const callback = await captureLogin(page, app);
  const before = await control('/stats');
  const crossed = new URL(callback); crossed.host = new URL(apps.nginx.origin).host; crossed.pathname = `/_autentico/${apps.nginx.id}/callback`;
  expect((await page.goto(crossed.toString()))!.status()).toBe(400);
  await shell(page, app);
  await context.addCookies([{ name: `__Host-autentico_fa_${app.id}`, value: 'a'.repeat(43), url: app.origin, secure: true, httpOnly: true }]);
  expect((await appFetch(page, '/private')).status).toBe(401);
  const duplicate = new URL(callback); duplicate.searchParams.append('state', duplicate.searchParams.get('state')!);
  expect((await page.goto(duplicate.toString()))!.status()).toBe(400);
  expect((await control('/stats')).hits).toBe(before.hits);
  await page.goto(callback); await page.waitForURL(app.origin + '/reports');
  const current = await appCookie(context, app);
  const status = await new Promise<number>((resolve, reject) => {
    const req = httpsRequest(app.origin + '/private', { family: 4, rejectUnauthorized: false,
      lookup: (_h, _o, done) => done(null, '127.0.0.1', 4),
      headers: { Accept: 'application/json', Cookie: `${current.name}=${current.value}; ${current.name}=forged` },
    }, response => { response.resume(); resolve(response.statusCode!); });
    req.on('error', reject); req.end();
  });
  expect(status).toBe(401);
});

test('cross-origin local logout is denied without revoking the owner session', async ({ page, context }) => {
  const app = apps.caddy; await login(page, app);
  const attacker = await context.newPage();
  await attacker.goto('https://evil.example.test:25443/');
  const target = `${app.origin}/_autentico/${app.id}/logout`;
  const rejected = attacker.waitForResponse(response => response.url() === target && response.request().method() === 'POST');
  await attacker.evaluate(url => fetch(url, { method: 'POST', credentials: 'include', mode: 'no-cors' }).then(() => undefined), target);
  expect((await rejected).status()).toBe(403);
  expect((await appFetch(page, '/private')).status).toBe(200);
  await attacker.close();
});

test('admin UI creates, edits and deletes app registrations with immutable origin and audit records', async ({ page }) => {
  await page.goto(fixture.auth + '/admin/protected-apps');
  await submitLogin(page, 'admin');
  await page.waitForURL(fixture.auth + '/admin/protected-apps');
  await page.getByRole('button', { name: 'Add Application' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Name', { exact: true }).fill('Proxy UI app');
  await dialog.getByLabel('Application origin', { exact: true }).fill('https://ui.example.test:25443');
  await dialog.getByLabel('Allowed path prefixes', { exact: true }).fill('/reports\n/status');
  await dialog.getByLabel('Session lifetime', { exact: true }).fill('30m');
  await dialog.getByRole('button', { name: 'OK', exact: true }).click();
  const row = page.getByRole('row').filter({ hasText: 'Proxy UI app' });
  await expect(row).toBeVisible();
  const all = await (await api('/admin/api/protected-apps')).json();
  const created = all.data.find((app: App) => app.name === 'Proxy UI app');
  expect(created.allowed_return_paths).toEqual(['/reports', '/status']);
  await row.getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(dialog.getByLabel('Application origin', { exact: true })).toBeDisabled();
  await dialog.getByLabel('Name', { exact: true }).fill('Edited proxy app');
  await dialog.getByRole('switch').click();
  await dialog.getByRole('button', { name: 'OK', exact: true }).click();
  const edited = page.getByRole('row').filter({ hasText: 'Edited proxy app' });
  await expect(edited.getByText('Disabled', { exact: true })).toBeVisible();
  await edited.getByRole('button', { name: 'Delete', exact: true }).click();
  await page.getByRole('tooltip').getByRole('button', { name: 'OK', exact: true }).click();
  await expect(edited).toHaveCount(0);
  const audit = await (await api('/admin/api/audit-logs?limit=100')).json();
  const events = audit.data.items.filter((event: { target_id: string }) => event.target_id === created.id).map((event: { event: string }) => event.event);
  expect(events).toEqual(expect.arrayContaining(['protected_app_created', 'protected_app_updated', 'protected_app_deleted']));
});

test('concurrent redemption through the real proxy issues exactly one session', async ({ page, context }) => {
  const app = apps.caddy;
  const callback = await captureLogin(page, app);
  const cookies = (await context.cookies(app.origin)).map(c => `${c.name}=${c.value}`).join('; ');
  const responses = await Promise.all(Array.from({ length: 8 }, () => new Promise<{ status: number; cookies: string[] }>((resolve, reject) => {
    const req = httpsRequest(callback, { family: 4, rejectUnauthorized: false,
      lookup: (_h, _o, done) => done(null, '127.0.0.1', 4), headers: { Cookie: cookies },
    }, response => { response.resume(); response.on('end', () => resolve({ status: response.statusCode!, cookies: response.headers['set-cookie'] ?? [] })); });
    req.on('error', reject); req.end();
  })));
  const winners = responses.filter(response => response.status === 303);
  expect(winners).toHaveLength(1);
  expect(responses.filter(response => response.status === 400)).toHaveLength(7);
  const name = `__Host-autentico_fa_${app.id}`;
  const credential = winners[0].cookies.find(cookie => cookie.startsWith(name + '='))!.split(';')[0].slice(name.length + 1);
  await context.addCookies([{ name, value: credential, url: app.origin, secure: true, httpOnly: true, sameSite: 'Lax' }]);
  const response = await page.goto(app.origin + '/reports'); expect(response!.status()).toBe(200);
});

test('active traffic preserves a short idle timeout while inactive traffic expires', async ({ page }) => {
  await settings({ sso_session_idle_timeout: '2s' });
  await login(page, apps.caddy);
  // Keep using the app beyond its idle limit. A naive 30s activity throttle
  // would reject these requests even though the browser remains active.
  for (let i = 0; i < 8; i++) {
    await new Promise(resolve => setTimeout(resolve, 400));
    expect((await appFetch(page, '/reports')).status).toBe(200);
  }
  await new Promise(resolve => setTimeout(resolve, 2200));
  expect((await appFetch(page, '/reports')).status).toBe(401);
});

test('moving the IdP site denies stale registrations but preserves admin listing and deletion', async ({ page }) => {
  const extra = await api('/admin/api/protected-apps', { name: 'Obsolete registration', origin: 'https://obsolete.example.test', allowed_return_paths: ['/'] });
  expect(extra.status).toBe(201);
  const obsolete = (await extra.json()).data as App;
  await login(page, apps.caddy);
  const oldToken = fixture.token;
  let healthy: App | undefined;
  try {
    await control('/relocate-auth');
    const token = await fetch(fixture.admin + '/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'password', client_id: 'autentico-admin', username: 'admin', password, scope: 'openid profile email' }),
    });
    expect(token.status).toBe(200);
    fixture.token = (await token.json()).access_token;
    expect((await appFetch(page, '/reports')).status).toBe(403);
    const created = await api('/admin/api/protected-apps', { name: 'Current-site registration', origin: 'https://healthy.other.test', allowed_return_paths: ['/'] });
    expect(created.status).toBe(201); healthy = (await created.json()).data as App;
    const listed = await api('/admin/api/protected-apps'); expect(listed.status).toBe(200);
    const registrations = (await listed.json()).data as App[];
    expect(registrations.map(app => app.id)).toEqual(expect.arrayContaining([obsolete.id, apps.caddy.id, healthy.id]));
    expect((await api(`/admin/api/protected-apps/${obsolete.id}`, undefined, 'DELETE')).status).toBe(204);
    expect((await api(`/admin/api/protected-apps/${healthy.id}`, undefined, 'DELETE')).status).toBe(204);
    healthy = undefined;
  } finally {
    if (healthy) await api(`/admin/api/protected-apps/${healthy.id}`, undefined, 'DELETE');
    await control('/restore-auth');
    fixture.token = oldToken;
    await api(`/admin/api/protected-apps/${obsolete.id}`, undefined, 'DELETE');
  }
  // The old registrations become usable again once their site is restored.
  expect((await appFetch(page, '/reports')).status).toBe(200);
});


test('public Caddy and nginx IdP vhosts block private routes despite forged forwarding headers', async ({ page, context }) => {
  await context.setExtraHTTPHeaders({ 'X-Forwarded-Host': new URL(apps.caddy.origin).host, 'X-Forwarded-Proto': 'https', 'X-Forwarded-Method': 'GET', 'X-Forwarded-Uri': '/reports' });
  for (const origin of [fixture.auth, fixture.authNginx]) {
    expect((await page.goto(origin + '/.well-known/openid-configuration'))!.status()).toBe(200);
    for (const path of ['/forward-auth', '/forward-auth/' + apps.caddy.id + '/check', '/_autentico', '/_autentico/' + apps.caddy.id + '/start?return=%2Freports', '/_autentico/' + apps.caddy.id + '/callback?state=forged']) {
      expect((await page.goto(origin + path))!.status(), origin + path).toBe(404);
    }
    expect((await appFetch(page, '/_autentico/' + apps.caddy.id + '/logout', 'POST')).status).toBe(404);
  }
});
