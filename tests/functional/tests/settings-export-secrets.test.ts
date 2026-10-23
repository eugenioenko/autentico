import { it, expect } from 'vitest';
import { BASE_URL, getAdminToken, putJSON, postJSON } from '../helpers';

it('omits SMTP credentials from export and accepts a round-trip import', async () => {
 const admin=await getAdminToken();
 const configured=await putJSON(`${BASE_URL}/admin/api/settings`,{smtp_password:'must-not-be-exported',smtp_username:'settings-export-user'},admin);
 expect(configured.ok).toBe(true);
 const response=await fetch(`${BASE_URL}/admin/api/settings/export`,{headers:{Authorization:`Bearer ${admin}`}});
 expect(response.status).toBe(200);
 const text=await response.text();
 expect(text).not.toContain('must-not-be-exported');
 const exported=JSON.parse(text).data;
 expect(exported.settings).not.toHaveProperty('smtp_password');
 expect(exported.settings).not.toHaveProperty('private_key');
 expect(exported.settings).not.toHaveProperty('onboarded');
 expect(exported.settings.smtp_username).toBe('settings-export-user');
 const imported=await postJSON(`${BASE_URL}/admin/api/settings/import/apply`,exported,admin);
 expect(imported.status).toBe(204);
});
