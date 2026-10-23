import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, putJSON, deleteRequest, getResponse } from '../helpers';

const API = `${BASE_URL}/admin/api`;
const events = [
  'group_created', 'group_updated', 'group_deleted', 'group_member_added',
  'group_member_removed', 'user_claim_upserted', 'user_claim_deleted',
];
type Entry = { event: string; actor_id: string; actor_username: string; target_type: string;
  target_id: string; detail: string; ip_address: string; created_at: string };

async function entries(token: string): Promise<Entry[]> {
  const result: Entry[] = [];
  for (const event of events) {
    const response = await getResponse(`${API}/audit-logs?event=${event}`, token);
    expect(response.status).toBe(200);
    const { data } = await response.json();
    expect(data.total).toBe(data.items.length);
    expect(data.items.every((item: Entry) => item.event === event)).toBe(true);
    result.push(...data.items);
  }
  return result;
}

describe('Group and custom-claim audit trail', () => {
  it('records actor, target and metadata for successful changes, excluding values and rejected requests', async () => {
    const token = await getAdminToken();
    expect((await putJSON(`${API}/settings`, { audit_log_retention: '-1' }, token)).status).toBe(204);
    const users = await getResponse(`${API}/users`, token);
    const actorID = (await users.json()).data.items.find((u: { username: string }) => u.username === 'admin').id;
    const created = await postJSON(`${API}/users`, { username: 'audit-user', password: 'Password123!' }, token);
    expect(created.status).toBe(201);
    const userID = (await created.json()).data.id;
    const response = await postJSON(`${API}/groups`, { name: 'audit-group' }, token);
    expect(response.status).toBe(201);
    const groupID = (await response.json()).data.id;
    const groupURL = `${API}/groups/${groupID}`;
    const claimURL = `${API}/users/${userID}/claims`;
    expect((await putJSON(groupURL, { name: 'audit-renamed' }, token)).status).toBe(200);
    expect((await postJSON(`${groupURL}/members`, { user_id: userID }, token)).status).toBe(201);
    expect((await postJSON(claimURL, { name: '  tier  ', value: 'private-original' }, token)).status).toBe(201);
    expect((await postJSON(claimURL, { name: 'tier', value: 'private-replacement' }, token)).status).toBe(201);

    const before = await entries(token);
    expect((await postJSON(`${API}/groups`, { name: 'audit-renamed' }, token)).status).toBe(409);
    expect((await postJSON(`${groupURL}/members`, { user_id: userID }, token)).status).toBe(409);
    expect((await postJSON(claimURL, { name: 'sub', value: 'forbidden' }, token)).status).toBe(400);
    expect((await putJSON(`${API}/groups/missing`, { name: 'missing' }, token)).status).toBe(404);
    expect((await postJSON(`${API}/users/missing/claims`, { name: 'tier', value: 'secret' }, token)).status).toBe(404);
    expect((await deleteRequest(`${claimURL}/missing`, token)).status).toBe(404);
    expect((await postJSON(`${API}/groups`, { name: 'unauthorized' })).status).toBe(401);
    expect((await postJSON(claimURL, { name: 'tier', value: 'unauthorized' })).status).toBe(401);
    for (const url of [groupURL, `${groupURL}/members`, claimURL]) {
      expect((await getResponse(url, token)).status).toBe(200);
    }
    expect(await entries(token)).toEqual(before);

    expect((await deleteRequest(`${groupURL}/members/${userID}`, token)).status).toBe(200);
    expect((await deleteRequest(`${groupURL}/members/${userID}`, token)).status).toBe(404);
    expect((await deleteRequest(`${claimURL}/tier`, token)).status).toBe(200);
    expect((await deleteRequest(groupURL, token)).status).toBe(200);
    expect((await deleteRequest(groupURL, token)).status).toBe(404);
    const logs = await entries(token);
    expect(logs).toHaveLength(8);
    for (const event of events) {
      const matching = logs.filter(item => item.event === event);
      expect(matching).toHaveLength(event === 'user_claim_upserted' ? 2 : 1);
      for (const entry of matching) {
        const isGroup = event.startsWith('group_');
        expect(entry).toMatchObject({ actor_id: actorID, actor_username: 'admin',
          target_type: isGroup ? 'group' : 'user', target_id: isGroup ? groupID : userID });
        expect(entry.ip_address).toBeTruthy();
        expect(Number.isNaN(Date.parse(entry.created_at))).toBe(false);
        expect(entry.detail ? JSON.parse(entry.detail) : {}).toEqual(event.startsWith('group_member_')
          ? { user_id: userID } : isGroup ? {} : { claim_name: 'tier' });
      }
    }
    expect(JSON.stringify(logs)).not.toContain('private-');
    const search = await getResponse(`${API}/audit-logs?event=group_member_added&search=${userID}`, token);
    expect((await search.json()).data.total).toBe(1);
  });

  it('honors disabled logging for all seven admin actions', async () => {
    const token = await getAdminToken();
    const before = await entries(token);
    expect((await putJSON(`${API}/settings`, { audit_log_retention: '0' }, token)).status).toBe(204);
    const response = await postJSON(`${API}/groups`, { name: 'no-audit' }, token);
    expect(response.status).toBe(201);
    const id = (await response.json()).data.id;
    const created = await postJSON(`${API}/users`, { username: 'no-audit-user', password: 'Password123!' }, token);
    expect(created.status).toBe(201);
    const userID = (await created.json()).data.id;
    const group = `${API}/groups/${id}`;
    const claims = `${API}/users/${userID}/claims`;
    expect((await putJSON(group, { name: 'no-audit-renamed' }, token)).status).toBe(200);
    expect((await postJSON(`${group}/members`, { user_id: userID }, token)).status).toBe(201);
    expect((await deleteRequest(`${group}/members/${userID}`, token)).status).toBe(200);
    expect((await postJSON(claims, { name: 'tier', value: 'secret' }, token)).status).toBe(201);
    expect((await deleteRequest(`${claims}/tier`, token)).status).toBe(200);
    expect((await deleteRequest(group, token)).status).toBe(200);
    expect(await entries(token)).toEqual(before);
  });
});
