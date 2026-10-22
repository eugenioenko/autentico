import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, putJSON, getResponse, deleteRequest, obtainTokenViaAuthCode } from '../helpers';

const API = `${BASE_URL}/admin/api`;
/** Read the real token subject to identify the authenticated account. */
function subject(token: string): string {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).sub;
}
/** Assert the public API conflict contract for a denied last-admin mutation. */
async function expectProtected(response: Response) {
  expect(response.status).toBe(409);
  expect(await response.json()).toMatchObject({ error: 'last_active_admin' });
}

// Each test preserves a working administrator for the next scenario.
describe.sequential('Last active administrator', () => {
  it('rejects self-demotion, deactivation and deletion without revoking access', async () => {
    const admin = await getAdminToken();
    const id = subject(admin);
    await expectProtected(await putJSON(`${API}/users/${id}`, { role: 'user' }, admin));
    await expectProtected(await postJSON(`${API}/users/${id}/deactivate`, {}, admin));
    await expectProtected(await deleteRequest(`${API}/users/${id}`, admin));
    const profile = await getResponse(`${API}/users/${id}`, admin);
    expect(profile.status).toBe(200);
    expect((await profile.json()).data.role).toBe('admin');
    const updated = await putJSON(`${API}/users/${id}`, { nickname: 'Admin still active' }, admin);
    expect(updated.status).toBe(200);
  });

  it('protects approval and immediate self-service deletion, preserving the pending request', async () => {
    const admin = await getAdminToken();
    const pending = await postJSON(`${BASE_URL}/account/api/deletion-request`, {}, admin);
    expect(pending.status).toBe(201);
    const request = (await pending.json()).data;
    await expectProtected(await postJSON(`${API}/deletion-requests/${request.id}/approve`, {}, admin));
    expect((await getResponse(`${BASE_URL}/account/api/deletion-request`, admin)).status).toBe(200);
    expect((await putJSON(`${API}/settings`, { allow_self_service_deletion: 'true' }, admin)).status).toBe(204);
    await expectProtected(await postJSON(`${BASE_URL}/account/api/deletion-request`, {}, admin));
    const unchanged = await getResponse(`${BASE_URL}/account/api/deletion-request`, admin);
    expect((await unchanged.json()).data.id).toBe(request.id);
    expect((await putJSON(`${API}/settings`, { allow_self_service_deletion: 'false' }, admin)).status).toBe(204);
    expect((await deleteRequest(`${BASE_URL}/account/api/deletion-request`, admin)).status).toBe(204);
  });

  it('allows removing a spare administrator but ignores inactive admins as replacements', async () => {
    const admin = await getAdminToken();
    for (const action of ['demote', 'deactivate', 'delete']) {
      const created = await postJSON(`${API}/users`, {
        username: `spare-${action}`, password: 'Password123!', email: `spare-${action}@test.com`, role: 'admin',
      }, admin);
      expect(created.status).toBe(201);
      const spare = (await created.json()).data.id;
      expect((await putJSON(`${API}/users/${spare}`, { role: 'admin' }, admin)).status).toBe(200);
      const response = action === 'demote'
        ? await putJSON(`${API}/users/${spare}`, { role: 'user' }, admin)
        : action === 'deactivate'
          ? await postJSON(`${API}/users/${spare}/deactivate`, {}, admin)
          : await deleteRequest(`${API}/users/${spare}`, admin);
      expect(response.status).toBe(action === 'demote' ? 200 : 204);
      await expectProtected(await putJSON(`${API}/users/${subject(admin)}`, { role: 'user' }, admin));
    }
  });

  it('serializes simultaneous removals through separate authenticated callers', async () => {
    let current = await getAdminToken();
    for (const [first, second] of [['demote', 'deactivate'], ['delete', 'demote'], ['deactivate', 'delete']]) {
      const name = `race-${first}-${second}`;
      const created = await postJSON(`${API}/users`, {
        username: name, password: 'Password123!', email: `${name}@test.com`, role: 'admin',
      }, current);
      expect(created.status).toBe(201);
      const spare = (await created.json()).data.id;
      expect((await putJSON(`${API}/users/${spare}`, { role: 'admin' }, current)).status).toBe(200);
      const other = await obtainTokenViaAuthCode(name, 'Password123!');
      const tokens = [current, other.access_token];
      const ids = tokens.map(subject);
      const responses = await Promise.all([first, second].map((action, i) => {
        const url = `${API}/users/${ids[i]}`;
        return action === 'demote' ? putJSON(url, { role: 'user' }, tokens[i])
          : action === 'delete' ? deleteRequest(url, tokens[i])
            : postJSON(`${url}/deactivate`, {}, tokens[i]);
      }));
      expect(responses.filter(response => response.status === 200 || response.status === 204)).toHaveLength(1);
      const survivor = responses.findIndex(response => response.status === 409);
      expect(survivor).toBeGreaterThanOrEqual(0);
      expect(await responses[survivor].json()).toMatchObject({ error: 'last_active_admin' });
      current = tokens[survivor];
      const listed = await getResponse(`${API}/users?role=admin`, current);
      expect(listed.status).toBe(200);
      expect((await listed.json()).data.items).toHaveLength(1);
    }
  });
});
