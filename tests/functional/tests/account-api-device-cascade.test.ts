import { describe, it, expect } from 'vitest';
import {
  BASE_URL,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  obtainTokenViaAuthCode,
  getResponse,
  deleteRequest,
} from '../helpers';

// Each call to obtainTokenViaAuthCode uses a fresh cookie jar (no state is
// carried between invocations), so two calls simulate two independent browser
// contexts — each produces its own idp_sessions row and an OAuth session
// linked to it via sessions.idp_session_id.
//
// Regression for issue #228: revoking one device via the account-ui
// "Devices" tab must cascade-kill every OAuth session born from that IdP
// session, without touching the other browser.

type DeviceRow = {
  id: string;
  user_agent: string;
  ip_address: string;
  last_activity_at: string;
  created_at: string;
  active_apps_count: number;
  is_current: boolean;
};

async function listDevices(token: string): Promise<DeviceRow[]> {
  const resp = await getResponse(`${BASE_URL}/account/api/sessions`, token);
  expect(resp.status).toBe(200);
  const body = (await resp.json()) as { data: DeviceRow[] };
  return body.data;
}

describe('Account API — device cascade revocation (issue #228)', () => {
  it('revoking device B from browser A kills token B everywhere; token A keeps working', async () => {
    // Two independent "browsers" log in as the same admin user. Each full
    // auth_code flow creates its own idp_sessions row.
    const browserA = await obtainTokenViaAuthCode(ADMIN_USERNAME, ADMIN_PASSWORD);
    const browserB = await obtainTokenViaAuthCode(ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(browserA.access_token).not.toBe(browserB.access_token);

    // Both tokens work against the account API before revocation.
    const profileA0 = await getResponse(`${BASE_URL}/account/api/profile`, browserA.access_token);
    expect(profileA0.status).toBe(200);
    const profileB0 = await getResponse(`${BASE_URL}/account/api/profile`, browserB.access_token);
    expect(profileB0.status).toBe(200);

    // Browser A sees at least its own device and browser B's device.
    const devicesFromA = await listDevices(browserA.access_token);
    expect(devicesFromA.length).toBeGreaterThanOrEqual(2);

    // Identify the "other" device (not the one marked current from A's POV).
    const otherFromA = devicesFromA.find((d) => !d.is_current);
    expect(otherFromA).toBeDefined();

    // Sanity: from B's POV, the same row is current.
    const devicesFromB = await listDevices(browserB.access_token);
    const currentFromB = devicesFromB.find((d) => d.is_current);
    expect(currentFromB?.id).toBe(otherFromA!.id);

    // Browser A revokes browser B's device via the account-api.
    const revoke = await deleteRequest(
      `${BASE_URL}/account/api/sessions/${otherFromA!.id}`,
      browserA.access_token,
    );
    expect(revoke.status).toBe(200);
    const revokeBody = await revoke.json();
    expect(revokeBody.data.message).toBe('Session revoked');

    // Token B is rejected at the OAuth2 userinfo endpoint.
    const userinfoB = await getResponse(`${BASE_URL}/oauth2/userinfo`, browserB.access_token);
    expect(userinfoB.status).toBe(401);

    // Token B is rejected at the account API.
    const profileB = await getResponse(`${BASE_URL}/account/api/profile`, browserB.access_token);
    expect(profileB.status).toBe(401);

    // Token A continues to work — cascade must be scoped to the revoked device.
    const profileA = await getResponse(`${BASE_URL}/account/api/profile`, browserA.access_token);
    expect(profileA.status).toBe(200);

    // Browser A's device list should no longer include the revoked row.
    const devicesAfter = await listDevices(browserA.access_token);
    expect(devicesAfter.find((d) => d.id === otherFromA!.id)).toBeUndefined();
  });
});
