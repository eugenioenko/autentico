import { beforeAll, describe, expect, it } from 'vitest';
import { BASE_URL, getAdminToken, obtainAccountToken, postJSON, putJSON, getResponse } from '../helpers';

const ADMIN = `${BASE_URL}/admin/api`;
const ACCOUNT = `${BASE_URL}/account/api`;
const PASSWORD = 'Password123!';
let admin: string;

/** Create a real account and obtain its own account-API credentials. */
async function account(name: string) {
  const created = await postJSON(`${ADMIN}/users`, { username: name, email: `${name}@test.com`, password: PASSWORD }, admin);
  expect(created.status).toBe(201);
  const user = (await created.json()).data;
  const tokens = await obtainAccountToken(name, PASSWORD);
  const profile = await getResponse(`${ACCOUNT}/profile`, tokens.access_token);
  expect(profile.status).toBe(200);
  expect((await profile.json()).data.has_password).toBe(true);
  return { id: user.id as string, token: tokens.access_token };
}

beforeAll(async () => {
  admin = await getAdminToken();
  expect((await putJSON(`${ADMIN}/settings`, { allow_self_service_deletion: 'true', audit_log_retention: '720h' }, admin)).status).toBe(204);
});

describe.sequential('Self-service deletion authentication', () => {
  for (const [name, body, status] of [
    ['missing', {}, 400], ['wrong', { current_password: 'wrong' }, 403],
  ] as const) {
    it(`rejects a ${name} password while preserving the account and session`, async () => {
      const user = await account(`delete-${name}`);
      const rejected = await postJSON(`${ACCOUNT}/deletion-request`, body, user.token);
      expect(rejected.status).toBe(status);
      expect((await getResponse(`${ACCOUNT}/profile`, user.token)).status).toBe(200);
      expect((await getResponse(`${ADMIN}/users/${user.id}`, admin)).status).toBe(200);
    });
  }

  it('fails closed on malformed JSON', async () => {
    const user = await account('delete-malformed');
    for (const body of ['{"current_password":', '{"current_password":"Password123!"} trailing', '{"current_password":"Password123!"} {}']) {
    const response = await fetch(`${ACCOUNT}/deletion-request`, { method: 'POST',
      headers: { Authorization: `Bearer ${user.token}`, 'Content-Type': 'application/json' }, body });
    expect(response.status).toBe(400);
    expect((await getResponse(`${ACCOUNT}/profile`, user.token)).status).toBe(200);
    }
  });

  it('deletes with the correct password, invalidates the credential and retains an audit record', async () => {
    const user = await account('delete-audited');
    const response = await postJSON(`${ACCOUNT}/deletion-request`, { current_password: PASSWORD }, user.token);
    expect(response.status).toBe(204);
    expect((await getResponse(`${ACCOUNT}/profile`, user.token)).status).toBe(401);
    expect((await getResponse(`${ADMIN}/users/${user.id}`, admin)).status).toBe(404);
    const audit = await getResponse(`${ADMIN}/audit-logs?event=user_deleted`, admin);
    expect(audit.status).toBe(200);
    const record = (await audit.json()).data.items.find((entry: { target_id: string }) => entry.target_id === user.id);
    expect(record).toMatchObject({ actor_id: user.id, actor_username: 'delete-audited', target_id: user.id });
    expect(JSON.stringify(record)).not.toContain(PASSWORD);
  });

  it('enforces the existing account password lockout', async () => {
    const user = await account('delete-locked');
    expect((await putJSON(`${ADMIN}/settings`, { account_lockout_max_attempts: '2', account_lockout_duration: '1m' }, admin)).status).toBe(204);
    for (let attempt = 0; attempt < 2; attempt++) {
      expect((await postJSON(`${ACCOUNT}/deletion-request`, { current_password: 'wrong' }, user.token)).status).toBe(403);
    }
    const locked = await postJSON(`${ACCOUNT}/deletion-request`, { current_password: PASSWORD }, user.token);
    expect(locked.status).toBe(429);
    expect(await locked.json()).toMatchObject({ error: 'account_locked' });
    expect((await getResponse(`${ADMIN}/users/${user.id}`, admin)).status).toBe(200);
  });

  it('does not require password confirmation merely to request admin review', async () => {
    const user = await account('delete-reviewed');
    expect((await putJSON(`${ADMIN}/settings`, { allow_self_service_deletion: 'false' }, admin)).status).toBe(204);
    const response = await postJSON(`${ACCOUNT}/deletion-request`, { reason: 'please remove' }, user.token);
    expect(response.status).toBe(201);
    expect((await response.json()).data.user_id).toBe(user.id);
    expect((await getResponse(`${ACCOUNT}/profile`, user.token)).status).toBe(200);
  });
});
