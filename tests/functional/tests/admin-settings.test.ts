import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, putJSON, getResponse, getJSON, postJSON } from '../helpers';

const API = `${BASE_URL}/admin/api/settings`;

describe('Admin Settings — happy path', () => {
  it('gets current settings', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(API, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.data).toBeTruthy();
    expect(typeof body.data).toBe('object');
  });

  it('updates a setting', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(API, {
      theme_title: 'Functional Test Title',
    }, token);
    expect(resp.ok).toBe(true);
  });

  it('verifies setting was updated', async () => {
    const token = await getAdminToken();
    const body = await getJSON<{ data: { theme_title: string } }>(API, token);
    expect(body.data.theme_title).toBe('Functional Test Title');
  });

  it('exports settings', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/export`, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body).toBeTruthy();
  });
});

describe('Admin Settings — error cases', () => {
  it('rejects GET without token', async () => {
    const resp = await getResponse(API);
    expect(resp.status).toBe(401);
  });

  it('rejects PUT without token', async () => {
    const resp = await putJSON(API, { theme_title: 'X' });
    expect(resp.status).toBe(401);
  });
});
