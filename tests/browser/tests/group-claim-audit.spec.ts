import { test, expect } from '@playwright/test';
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD } from '../server-manager';

const options = [
  ['Group Created', 'group_created'], ['Group Updated', 'group_updated'],
  ['Group Deleted', 'group_deleted'], ['Group Member Added', 'group_member_added'],
  ['Group Member Removed', 'group_member_removed'], ['User Claim Upserted', 'user_claim_upserted'],
  ['User Claim Deleted', 'user_claim_deleted'],
];

test.beforeAll(async () => {
  await startServer();
  const token = await getAdminToken();
  await updateSettings(token, { audit_log_retention: '-1' });
  const response = await fetch(`${BASE_URL}/admin/api/groups`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'browser-audit' }),
  });
  expect(response.status).toBe(201);
});
test.afterAll(() => stopServer());

test('group and claim event filters query the API and show audit entries', async ({ page }) => {
  await page.goto(`${BASE_URL}/admin/audit-log`);
  await page.waitForURL('**/oauth2/authorize**');
  await page.fill('#username', ADMIN_USERNAME);
  await page.fill('#password', ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${BASE_URL}/admin/audit-log`);
  for (const [label, event] of options) {
    await page.getByLabel('Filter audit events').click();
    // The event menu virtualizes its long list; the new event types are at the end.
    await page.locator('.ant-select-dropdown:visible .ant-select-dropdown-list-holder').evaluate(element => {
      element.scrollTop = element.scrollHeight;
    });
    const response = page.waitForResponse(response =>
      response.url().includes('/admin/api/audit-logs?') && new URL(response.url()).searchParams.get('event') === event);
    await page.locator('.ant-select-dropdown:visible').getByText(label, { exact: true }).click();
    expect((await response).status()).toBe(200);
    if (event === 'group_created') {
      const row = page.getByRole('row').filter({ hasText: 'Group Created' });
      await expect(row).toContainText('admin');
      await expect(row).toContainText('group:');
    } else await expect(page.locator('.ant-empty-description')).toBeVisible();
  }
});
