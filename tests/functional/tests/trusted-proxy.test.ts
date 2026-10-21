import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawn, spawnSync, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const binary = join(import.meta.dirname, '../../../autentico');
const baseURL = 'http://127.0.0.1:19995';

for (const trusted of [false, true]) {
  describe(`Client IP with trusted proxies ${trusted ? 'configured' : 'unset'}`, () => {
    let directory: string;
    let server: ChildProcess | undefined;
    let env: NodeJS.ProcessEnv;
    let logs = '';

    async function stop(): Promise<void> {
      if (server && server.exitCode === null) {
        await new Promise<void>((resolve) => {
          server!.once('exit', () => resolve());
          server!.kill('SIGTERM');
        });
      }
      server = undefined;
    }

    async function start(limited: boolean): Promise<void> {
      logs = '';
      server = spawn(binary, ['start'], {
        cwd: directory,
        env: { ...env, AUTENTICO_RATE_LIMIT_RPS: limited ? '0.001' : '0', AUTENTICO_RATE_LIMIT_BURST: '1', AUTENTICO_RATE_LIMIT_RPM: '0' },
        stdio: 'pipe',
      });
      server.stdout?.on('data', (data: Buffer) => { logs += data.toString(); });
      server.stderr?.on('data', (data: Buffer) => { logs += data.toString(); });
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        try { if ((await fetch(`${baseURL}/healthz`)).ok) return; } catch {}
        if (server.exitCode !== null) throw new Error(`Proxy test server exited: ${logs}`);
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      throw new Error(`Proxy test server did not start: ${logs}`);
    }

    beforeAll(async () => {
      directory = mkdtempSync(join(tmpdir(), 'autentico-proxy-'));
      env = {
        ...process.env,
        AUTENTICO_DB_FILE_PATH: join(directory, 'auth.db'),
        AUTENTICO_TRUSTED_PROXIES: trusted ? '127.0.0.1/32,::1/128' : '',
        AUTENTICO_CSRF_SECURE_COOKIE: 'false',
        AUTENTICO_IDP_SESSION_SECURE: 'false',
      };
      execFileSync(binary, ['init', '--url', baseURL], { cwd: directory, env });
      execFileSync(binary, ['onboard', '--username', 'admin', '--password', 'Password123!', '--email', 'admin@test.com', '--enable-admin-password-grant'], { cwd: directory, env });
      await start(false);
    });

    afterAll(async () => {
      await stop();
      if (directory) rmSync(directory, { recursive: true, force: true });
    });

    it('uses the same verified address in sessions and audit logs', async () => {
      const forwarded = trusted ? '203.0.113.200, 198.51.100.10' : '203.0.113.200';
      const expectedIP = trusted ? '198.51.100.10' : '127.0.0.1';
      const response = await fetch(`${baseURL}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': forwarded, 'User-Agent': 'proxy-regression' },
        body: new URLSearchParams({ grant_type: 'password', username: 'admin', password: 'Password123!', client_id: 'autentico-admin', scope: 'openid profile email' }),
      });
      expect(response.status).toBe(200);
      const { access_token } = await response.json();
      const headers = { Authorization: `Bearer ${access_token}`, 'X-Forwarded-For': forwarded };
      const sessionsResponse = await fetch(`${baseURL}/admin/api/sessions`, { headers });
      expect(sessionsResponse.status).toBe(200);
      const sessions = await sessionsResponse.json();
      expect(sessions.data.find((session: { user_agent: string }) => session.user_agent === 'proxy-regression').ip_address).toBe(expectedIP);
      const settings = await fetch(`${baseURL}/admin/api/settings`, {
        method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ allow_self_signup: 'false' }),
      });
      expect(settings.status).toBe(204);
      const auditResponse = await fetch(`${baseURL}/admin/api/audit-logs`, { headers });
      expect(auditResponse.status).toBe(200);
      const audit = await auditResponse.json();
      expect(audit.data.items.find((entry: { event: string }) => entry.event === 'settings_updated').ip_address).toBe(expectedIP);
    });

    it('cannot bypass the production token rate limiter by rotating forwarding headers', async () => {
      await stop();
      await start(true);
      for (let i = 1; i <= 30; i++) {
        const forged = `203.0.113.${i}`;
        const response = await fetch(`${baseURL}/oauth2/token`, {
          method: 'POST',
          headers: { 'X-Forwarded-For': trusted ? `${forged}, 198.51.100.10` : forged, 'X-Real-IP': forged },
        });
        expect(response.status).toBe(i === 1 ? 400 : 429);
      }
      if (trusted) {
        const otherClient = await fetch(`${baseURL}/oauth2/token`, { method: 'POST', headers: { 'X-Forwarded-For': '203.0.113.99, 198.51.100.11' } });
        expect(otherClient.status).toBe(400); // A different real client has its own budget.
      }
    });

    it('fails startup clearly for an invalid trusted-proxy CIDR', () => {
      const result = spawnSync(binary, ['start'], { cwd: directory, env: { ...env, AUTENTICO_TRUSTED_PROXIES: '127.0.0.1/32,not-a-cidr' }, encoding: 'utf8', timeout: 5000 });
      expect(result.status).toBe(1);
      expect(result.stdout + result.stderr).toContain('invalid AUTENTICO_TRUSTED_PROXIES');
    });
  });
}
