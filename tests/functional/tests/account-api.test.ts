import { describe, it, expect } from 'vitest';
import { BASE_URL, obtainTokenViaROPC, postJSON, deleteRequest, getResponse } from '../helpers';

const API = `${BASE_URL}/account/api/deletion-request`;

describe('Account Self-Service — happy path', () => {
  it('requests account deletion', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');

    const resp = await postJSON(API, {}, tokens.access_token);
    expect(resp.status).toBe(201);
  });

  it('gets pending deletion request', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');

    const resp = await getResponse(API, tokens.access_token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.data).toBeTruthy();
  });

  it('cancels deletion request', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');

    const resp = await deleteRequest(API, tokens.access_token);
    expect(resp.ok).toBe(true);
  });

  it('no pending request after cancel', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');

    const resp = await getResponse(API, tokens.access_token);
    // After cancellation, there's no pending request — server may return 404 or empty
    if (resp.ok) {
      const body = await resp.json();
      expect(body.data).toBeFalsy();
    } else {
      expect(resp.status).toBe(404);
    }
  });
});

describe('Account Self-Service — error cases', () => {
  it('rejects POST without token', async () => {
    const resp = await postJSON(API, {});
    expect(resp.status).toBe(401);
  });

  it('rejects GET without token', async () => {
    const resp = await getResponse(API);
    expect(resp.status).toBe(401);
  });

  it('rejects DELETE without token', async () => {
    const resp = await deleteRequest(API);
    expect(resp.status).toBe(401);
  });
});
