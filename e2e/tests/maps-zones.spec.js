// Maps zone management (Phase 2): section rendering, route-consent default,
// and server-side bbox validation — all without queueing anything, so no
// worker can ever fire and the run stays hermetic (no network, no disk).
const { test, expect } = require('@playwright/test');
const { freshPage, closePage } = require('../helpers');

async function login(page) {
  await page.goto('/admin/index.php');
  const form = page.locator('form[action="/admin/login.php"]');
  await form.locator('input[name="username"]').fill('e2e_owner');
  await form.locator('input[name="password"]').fill('E2eOwnerPass1!');
  await form.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/admin\/orders\.php/);
}

test('zones section renders with route consent defaulting to proxy', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await login(page);
    await page.goto('/admin/settings.php');
    await expect(page.locator('#maps-table, #maps-empty').first()).toBeVisible();
    await expect(page.locator('#mz-name')).toBeVisible();
    await expect(page.locator('#mz-maxzoom')).toBeVisible();
    // Proxy routing is off in the e2e database, so direct is pre-selected.
    await expect(page.locator('input[name="mz-via"][value="0"]')).toBeChecked();
    await expect(page.locator('#maps-disk')).toContainText('Free disk:');
  } finally {
    await closePage(page);
  }
});

test('non-numeric bbox is rejected with an error popup', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await login(page);
    await page.goto('/admin/settings.php');
    await page.locator('#mz-name').fill('E2E Bad Zone');
    await page.locator('#mz-min-lon').fill('not-a-number');
    await page.locator('#mz-min-lat').fill('52.05');
    await page.locator('#mz-max-lon').fill('21.30');
    await page.locator('#mz-max-lat').fill('52.40');
    await page.locator('#mz-add').click();
    const popup = page.locator('#save-popup.visible.error');
    await expect(popup).toBeVisible({ timeout: 10000 });
    expect(await popup.textContent()).toMatch(/numbers/i);
    // Nothing queued: no row for the rejected zone appears (the seeded
    // 'E2E Reveal Zone' ready row from seed.php may legitimately be there).
    expect(await page.locator('#maps-table tbody tr', { hasText: 'E2E Bad Zone' }).count()).toBe(0);
  } finally {
    await closePage(page);
  }
});

test('stale ready zone offers refresh and re-queues on click', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await login(page);
    await page.goto('/admin/settings.php');
    // Seeded ready zone with an older build than the cached planet build.
    const row = page.locator('#maps-table tbody tr', { hasText: 'E2E Reveal Zone' });
    await expect(row).toBeVisible();
    await expect(row).toContainText('Update available');
    // Runs last in this file: re-queueing leaves the zone queued (no worker
    // runs in e2e), which later files never depend on as ready.
    await row.locator('.mz-refresh').click();
    await expect(row).toContainText('Queued', { timeout: 10000 });
    expect(await row.locator('.mz-refresh').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});
