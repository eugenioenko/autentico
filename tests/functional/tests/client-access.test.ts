import { describe, it, expect, beforeAll } from 'vitest';
import {
  BASE_URL, OAUTH_URL, getAdminToken, getResponse, postForm, postJSON, putJSON, deleteRequest,
  obtainAuthorizationCode, obtainAccountToken,
} from '../helpers';

const API = `${BASE_URL}/admin/api`;
const REDIRECT_URI = 'http://localhost:3000/callback';
const PASSWORD = 'Password123!';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

let admin: string;
const users: Record<string, string> = {};
let staffGroup: string;
let opsGroup: string;

async function createUser(username: string): Promise<string> {
  const resp = await postJSON(`${API}/users`, { username, password: PASSWORD, email: `${username}@example.com` }, admin);
  expect(resp.status).toBe(201);
  return (await resp.json()).data.id;
}

async function createGroup(name: string): Promise<string> {
  const resp = await postJSON(`${API}/groups`, { name }, admin);
  expect(resp.status).toBe(201);
  return (await resp.json()).data.id;
}

async function addMember(groupID: string, userID: string): Promise<void> {
  expect((await postJSON(`${API}/groups/${groupID}/members`, { user_id: userID }, admin)).status).toBe(201);
}

async function createClient(clientID: string, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const resp = await postJSON(`${API}/clients`, {
    client_id: clientID,
    client_name: `Access ${clientID}`,
    redirect_uris: [REDIRECT_URI],
    grant_types: ['authorization_code', 'password', 'refresh_token', DEVICE_GRANT],
    scopes: 'openid profile email offline_access',
    client_type: 'public',
    token_endpoint_auth_method: 'none',
    ...extra,
  }, admin);
  const body = await resp.json();
  expect(resp.status, JSON.stringify(body)).toBe(201);
  return body;
}

async function getClient(clientID: string): Promise<Record<string, any>> {
  const resp = await getResponse(`${API}/clients/${clientID}`, admin);
  expect(resp.status).toBe(200);
  return resp.json();
}

async function ropc(clientID: string, username: string) {
  return postForm(`${OAUTH_URL}/token`, {
    grant_type: 'password', client_id: clientID, username, password: PASSWORD, scope: 'openid offline_access',
  });
}

function authorizeURL(clientID: string, state: string, prompt = ''): string {
  const url = new URL(`${OAUTH_URL}/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code', client_id: clientID, redirect_uri: REDIRECT_URI, scope: 'openid profile email',
    state, code_challenge: CHALLENGE, code_challenge_method: 'S256', ...(prompt ? { prompt } : {}),
  }).toString();
  return url.toString();
}

/** Runs the browser login form and returns the redirect target without following it. */
async function browserLogin(clientID: string, username: string, state: string): Promise<{ location: URL; cookies: string[] }> {
  const page = await fetch(authorizeURL(clientID, state), { redirect: 'manual' });
  expect(page.status).toBe(200);
  const html = await page.text();
  const csrf = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/)![1];
  const sig = html.match(/name="authorize_sig"\s+value="([^"]*)"/)?.[1] ?? '';
  const csrfCookie = page.headers.getSetCookie().find(c => c.startsWith('_gorilla_csrf='))!.split(';')[0];
  const resp = await fetch(`${OAUTH_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: csrfCookie, Origin: BASE_URL },
    body: new URLSearchParams({
      username, password: PASSWORD, 'gorilla.csrf.Token': csrf, authorize_sig: sig, client_id: clientID,
      redirect_uri: REDIRECT_URI, scope: 'openid profile email', state, response_type: 'code',
      code_challenge: CHALLENGE, code_challenge_method: 'S256',
    }),
    redirect: 'manual',
  });
  expect(resp.status).toBe(302);
  return { location: new URL(resp.headers.get('Location')!, BASE_URL), cookies: resp.headers.getSetCookie() };
}

function expectAccessDenied(location: URL, state: string): void {
  expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
  expect(location.searchParams.get('error')).toBe('access_denied');
  expect(location.searchParams.get('state')).toBe(state);
  expect(location.searchParams.get('code')).toBeNull();
}

async function exchange(clientID: string, code: string) {
  return postForm(`${OAUTH_URL}/token`, {
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientID, code_verifier: VERIFIER,
  });
}

describe('Client access restriction (black box)', () => {
  beforeAll(async () => {
    admin = await getAdminToken();
    expect((await putJSON(`${API}/settings`, { audit_log_retention: '-1' }, admin)).status).toBe(204);
    for (const name of ['direct', 'member', 'second', 'outsider']) {
      users[name] = await createUser(`ca-${name}`);
    }
    staffGroup = await createGroup('ca-staff');
    opsGroup = await createGroup('ca-ops');
    await addMember(staffGroup, users.member);
    await addMember(opsGroup, users.second);
  });

  describe('admin API', () => {
    it('creates, reads, lists and updates access settings', async () => {
      const created = await createClient('ca-crud', {
        restrict_access: true, allowed_groups: [staffGroup, staffGroup], allowed_users: [users.direct],
      });
      expect(created.restrict_access).toBe(true);
      expect(created.allowed_groups).toEqual([staffGroup]);
      expect(created.allowed_users).toEqual([users.direct]);

      const read = await getClient('ca-crud');
      expect(read).toMatchObject({ restrict_access: true, allowed_groups: [staffGroup], allowed_users: [users.direct] });

      const list = await (await getResponse(`${API}/clients?search=ca-crud`, admin)).json();
      const listed = list.data.items.find((c: { client_id: string }) => c.client_id === 'ca-crud');
      expect(listed).toMatchObject({ restrict_access: true, allowed_groups: [staffGroup], allowed_users: [users.direct] });

      const renamed = await putJSON(`${API}/clients/ca-crud`, { client_name: 'Renamed' }, admin);
      expect(renamed.status).toBe(200);
      expect(await renamed.json()).toMatchObject({ client_name: 'Renamed', restrict_access: true, allowed_groups: [staffGroup] });

      const replaced = await putJSON(`${API}/clients/ca-crud`, { allowed_groups: [opsGroup], allowed_users: [] }, admin);
      expect(replaced.status).toBe(200);
      expect(await replaced.json()).toMatchObject({ allowed_groups: [opsGroup], allowed_users: [] });

      const opened = await putJSON(`${API}/clients/ca-crud`, { restrict_access: false }, admin);
      expect(await opened.json()).toMatchObject({ restrict_access: false, allowed_groups: [opsGroup] });
    });

    it('defaults new clients to unrestricted with empty lists', async () => {
      await createClient('ca-default');
      expect(await getClient('ca-default')).toMatchObject({ restrict_access: false, allowed_groups: [], allowed_users: [] });
    });

    it('rejects unknown groups and users without partial writes', async () => {
      await createClient('ca-invalid', { restrict_access: true, allowed_groups: [staffGroup] });
      for (const body of [
        { allowed_groups: [opsGroup, 'missing-group'] },
        { allowed_users: ['missing-user'] },
        { restrict_access: false, allowed_groups: ['missing-group'] },
      ]) {
        const resp = await putJSON(`${API}/clients/ca-invalid`, body, admin);
        expect(resp.status).toBe(400);
        expect((await resp.json()).error).toBe('invalid_client_metadata');
      }
      expect(await getClient('ca-invalid')).toMatchObject({ restrict_access: true, allowed_groups: [staffGroup] });

      const create = await postJSON(`${API}/clients`, {
        client_id: 'ca-invalid-new', client_name: 'x', redirect_uris: [REDIRECT_URI], allowed_users: ['missing-user'],
      }, admin);
      expect(create.status).toBe(400);
      expect((await getResponse(`${API}/clients/ca-invalid-new`, admin)).status).toBe(404);
    });

    it('refuses to restrict the built-in admin and account clients', async () => {
      for (const id of ['autentico-admin', 'autentico-account']) {
        for (const body of [{ restrict_access: true }, { allowed_groups: [staffGroup] }, { allowed_users: [users.direct] }]) {
          const resp = await putJSON(`${API}/clients/${id}`, body, admin);
          expect(resp.status).toBe(400);
          expect((await resp.json()).error).toBe('invalid_client_metadata');
        }
        expect(await getClient(id)).toMatchObject({ restrict_access: false, allowed_groups: [], allowed_users: [] });
      }
    });

    it('requires an admin token', async () => {
      expect((await putJSON(`${API}/clients/ca-default`, { restrict_access: true })).status).toBe(401);
      expect((await getClient('ca-default')).restrict_access).toBe(false);
    });
  });

  describe('enforcement', () => {
    beforeAll(async () => {
      await createClient('ca-app', { restrict_access: true, allowed_groups: [staffGroup], allowed_users: [users.direct] });
    });

    it('password grant admits allowed users and refuses others with invalid_grant', async () => {
      for (const name of ['direct', 'member']) {
        expect((await ropc('ca-app', `ca-${name}`)).status).toBe(200);
      }
      for (const name of ['second', 'outsider']) {
        const resp = await ropc('ca-app', `ca-${name}`);
        expect(resp.status).toBe(400);
        const body = await resp.json();
        expect(body.error).toBe('invalid_grant');
        expect(body.access_token).toBeUndefined();
        expect(JSON.stringify(body)).not.toContain('ca-staff');
      }
    });

    it('wrong passwords are rejected before access is evaluated', async () => {
      const resp = await postForm(`${OAUTH_URL}/token`, {
        grant_type: 'password', client_id: 'ca-app', username: 'ca-outsider', password: 'wrong',
      });
      expect((await resp.json()).error_description).toBe('Invalid username or password');
    });

    it('browser login issues a code to allowed users and access_denied to others', async () => {
      const allowed = await browserLogin('ca-app', 'ca-member', 'st-allowed');
      const code = allowed.location.searchParams.get('code');
      expect(code).toBeTruthy();
      expect((await exchange('ca-app', code!)).status).toBe(200);

      const denied = await browserLogin('ca-app', 'ca-outsider', 'st-denied');
      expectAccessDenied(denied.location, 'st-denied');
      expect(denied.cookies.some(c => c.includes('autentico_idp_session='))).toBe(false);
    });

    it('SSO from another client does not bypass the restriction', async () => {
      await createClient('ca-open');
      const { idpSessionCookie } = await obtainAuthorizationCode('ca-open', REDIRECT_URI, 'ca-outsider', PASSWORD);
      expect(idpSessionCookie).toBeTruthy();

      for (const prompt of ['', 'none']) {
        const resp = await fetch(authorizeURL('ca-app', 'st-sso', prompt), { headers: { Cookie: idpSessionCookie }, redirect: 'manual' });
        expect(resp.status).toBe(302);
        expectAccessDenied(new URL(resp.headers.get('Location')!), 'st-sso');
      }
      const open = await fetch(authorizeURL('ca-open', 'st-open', 'none'), { headers: { Cookie: idpSessionCookie }, redirect: 'manual' });
      expect(new URL(open.headers.get('Location')!).searchParams.get('code')).toBeTruthy();
    });

    it('refresh stops working once the user leaves the allowed group', async () => {
      const userID = await createUser('ca-leaver');
      await addMember(staffGroup, userID);
      const first = await ropc('ca-app', 'ca-leaver');
      expect(first.status).toBe(200);
      const { refresh_token } = await first.json();

      expect((await deleteRequest(`${API}/groups/${staffGroup}/members/${userID}`, admin)).status).toBe(200);
      const refreshed = await postForm(`${OAUTH_URL}/token`, { grant_type: 'refresh_token', refresh_token, client_id: 'ca-app' });
      expect(refreshed.status).toBe(400);
      expect((await refreshed.json()).error).toBe('invalid_grant');
    });

    it('a code issued before restriction cannot be exchanged after it', async () => {
      await createClient('ca-late');
      const { location } = await browserLogin('ca-late', 'ca-outsider', 'st-late');
      const code = location.searchParams.get('code');
      expect(code).toBeTruthy();
      expect((await putJSON(`${API}/clients/ca-late`, { restrict_access: true }, admin)).status).toBe(200);
      const resp = await exchange('ca-late', code!);
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe('invalid_grant');
    });

    it('removing restriction restores access immediately', async () => {
      await createClient('ca-toggle', { restrict_access: true });
      expect((await ropc('ca-toggle', 'ca-outsider')).status).toBe(400);
      expect((await putJSON(`${API}/clients/ca-toggle`, { restrict_access: false }, admin)).status).toBe(200);
      expect((await ropc('ca-toggle', 'ca-outsider')).status).toBe(200);
    });

    it('deleting the only allowed group locks the client instead of opening it', async () => {
      const groupID = await createGroup('ca-temp');
      const userID = await createUser('ca-temp-user');
      await addMember(groupID, userID);
      await createClient('ca-fail-closed', { restrict_access: true, allowed_groups: [groupID] });
      expect((await ropc('ca-fail-closed', 'ca-temp-user')).status).toBe(200);

      expect((await deleteRequest(`${API}/groups/${groupID}`, admin)).status).toBe(200);
      expect(await getClient('ca-fail-closed')).toMatchObject({ restrict_access: true, allowed_groups: [] });
      for (const name of ['ca-temp-user', 'ca-outsider', 'ca-direct']) {
        expect((await ropc('ca-fail-closed', name)).status).toBe(400);
      }
    });

    it('deleting an allowed user removes them from the list', async () => {
      const userID = await createUser('ca-deleted');
      await createClient('ca-user-list', { restrict_access: true, allowed_users: [userID, users.direct] });
      expect((await deleteRequest(`${API}/users/${userID}`, admin)).status).toBeLessThan(300);
      expect((await getClient('ca-user-list')).allowed_users).toEqual([users.direct]);
    });

    it('device approval is refused for users outside the lists and leaves the request pending', async () => {
      const issued = await postForm(`${OAUTH_URL}/device_authorization`, { client_id: 'ca-app', scope: 'openid' });
      expect(issued.status).toBe(200);
      const { device_code, user_code } = await issued.json();

      const outsider = await obtainAccountToken('ca-outsider', PASSWORD);
      const refused = await postJSON(`${BASE_URL}/account/api/device/authorize`, { user_code }, outsider.access_token);
      expect(refused.status).toBe(403);
      expect((await refused.json()).error).toBe('access_denied');
      const pending = await postForm(`${OAUTH_URL}/token`, { grant_type: DEVICE_GRANT, device_code, client_id: 'ca-app' });
      expect((await pending.json()).error).toBe('authorization_pending');

      const member = await obtainAccountToken('ca-member', PASSWORD);
      const approved = await postJSON(`${BASE_URL}/account/api/device/authorize`, { user_code }, member.access_token);
      expect(approved.status).toBe(200);
      await new Promise(r => setTimeout(r, 5100));
      const granted = await postForm(`${OAUTH_URL}/token`, { grant_type: DEVICE_GRANT, device_code, client_id: 'ca-app' });
      expect(granted.status).toBe(200);
      expect((await granted.json()).access_token).toBeTruthy();
    }, 20000);

    it('the account dashboard lists only applications the user can open', async () => {
      await createClient('ca-dash-open', { show_in_account: true });
      await createClient('ca-dash-staff', { show_in_account: true, restrict_access: true, allowed_groups: [staffGroup] });
      await createClient('ca-dash-locked', { show_in_account: true, restrict_access: true });
      const appIDs = async (username: string) => {
        const { access_token } = await obtainAccountToken(username, PASSWORD);
        const resp = await getResponse(`${BASE_URL}/account/api/apps`, access_token);
        expect(resp.status).toBe(200);
        return (await resp.json()).data.map((a: { client_id: string }) => a.client_id).filter((id: string) => id.startsWith('ca-dash'));
      };
      expect((await appIDs('ca-member')).sort()).toEqual(['ca-dash-open', 'ca-dash-staff']);
      expect(await appIDs('ca-outsider')).toEqual(['ca-dash-open']);
    });

    it('records refusals in the audit log without group names', async () => {
      const resp = await getResponse(`${API}/audit-logs?event=client_access_denied`, admin);
      expect(resp.status).toBe(200);
      const { data } = await resp.json();
      expect(data.total).toBeGreaterThan(0);
      const flows = new Set<string>();
      for (const entry of data.items) {
        expect(entry.target_type).toBe('client');
        const detail = JSON.parse(entry.detail);
        expect(Object.keys(detail).sort()).toEqual(['flow', 'user_id']);
        flows.add(detail.flow);
      }
      for (const flow of ['password', 'refresh_token', 'authorization_code', 'sso', 'device_code']) {
        expect(flows.has(flow), flow).toBe(true);
      }
      expect(JSON.stringify(data.items)).not.toContain('ca-staff');
    });
  });
});
