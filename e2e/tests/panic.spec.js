// Panic wipe through the real three-step flow: counts previewed, wipe
// executed, session destroyed, backups directory emptied. This wipes the
// SHARED e2e database, so the file reseeds first (the wipe then destroys
// real seeded rows, never an already-empty database) and last (later files
// get fixtures, and the final login proves the app works post-wipe).
const { test, expect } = require('@playwright/test');
const { freshPage, closePage, reseed } = require('../helpers');

async function login(page) {
  await page.goto('/admin/index.php');
  const form = page.locator('form[action="/admin/login.php"]');
  await form.locator('input[name="username"]').fill('e2e_owner');
  await form.locator('input[name="password"]').fill('E2eOwnerPass1!');
  await form.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/admin\/orders\.php/);
}

// The step form on the current page, scoped by its hidden step field.
function stepForm(page, step) {
  return page.locator('form[action="/admin/panic.php"]', {
    has: page.locator(`input[name="step"][value="${step}"]`),
  });
}

test('wipe walks all three steps and logs out', async ({ browser }) => {
  reseed();
  const page = await freshPage(browser);
  try {
    await login(page);
    await page.goto('/admin/panic.php');

    await expect(stepForm(page, 1)).toBeVisible();
    await stepForm(page, 1).locator('button[type="submit"]').click();

    await expect(stepForm(page, 2)).toBeVisible();
    await stepForm(page, 2).locator('button[type="submit"]').click();

    // Step 3 previews what is about to die: the counts must be real seeded
    // rows (orders ≥ 5 after the re-seed), or the wipe below proves nothing.
    await expect(page.locator('.panic-counts')).toBeVisible();
    const orders = parseInt(await page.locator('.panic-counts-row span').first().textContent(), 10);
    expect(orders).toBeGreaterThanOrEqual(5);
    await stepForm(page, 3).locator('button[type="submit"]').click();

    // Done report with per-table counts, and the session is dead: the
    // relogin button lands on the login form, not back inside.
    await expect(page.locator('.panic-report')).toBeVisible();
    await page.locator('a[href="/admin/index.php"]').click();
    await expect(page.locator('form[action="/admin/login.php"]')).toBeVisible();
  } finally {
    await closePage(page);
  }
});

test('wiped lists stay empty, then fixtures come back', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    // Users survive the wipe, so login still works — but every evidence
    // table and the backups directory are empty.
    await login(page);
    await page.goto('/admin/backups.php');
    await expect(page.locator('tbody span.token')).toHaveCount(0);
    await page.goto('/admin/orders.php');
    await expect(page.locator('tr', { hasText: 'E2EADMDELIV00001' })).toHaveCount(0);

    // Restore the world for every later file, then prove the app is fully
    // functional again on the recovered rows.
    reseed();
    await login(page);
    await expect(page.locator('tr', { hasText: 'E2EADMDELIV00001' })).toHaveCount(1);
  } finally {
    await closePage(page);
  }
});
