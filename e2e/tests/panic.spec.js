// Panic wipe through the real three-step flow: counts previewed, wipe
// executed, session destroyed, backups directory emptied. This wipes the
// SHARED e2e database, so each test reseeds first (the wipe then destroys
// real seeded rows, never an already-empty database) and the file reseeds
// last (later files get fixtures, and the final login proves the app works
// post-wipe). Each test owns its wipe end to end: CI retries a failed test
// at the END of the suite, after other files reseeded — asserting on a
// wipe performed by an earlier test would be order-fragile by construction.
//
// Budgets are generous on purpose: the wipe synchronously overwrites every
// backup bundle, log and photo (the server arms set_time_limit(0) for
// exactly this), which took ~40 s on a loaded CI runner holding php -S's
// single thread. A 30 s default budget would kill the test while the
// server keeps wiping with ignore_user_abort — orphan state underfoot.
const { test, expect } = require('@playwright/test');
const { freshPage, closePage, reseed } = require('../helpers');

async function login(page) {
  const resp = await page.goto('/admin/index.php');
  // Fail fast and loud instead of hanging a whole test budget: a missing
  // form means the session is unexpectedly alive (stale login after a
  // wipe/logout — a session-lifecycle bug worth screaming about), the
  // bootstrap form showed (users table gone), or a white-screen 500.
  // The trace then shows the actual page instead of a bare timeout.
  expect(resp && resp.ok(), 'index.php must answer 2xx, not a white-screen 500').toBe(true);
  await expect(page, 'must be logged out at login entry, not redirected inside').not.toHaveURL(/admin\/orders\.php/, { timeout: 15000 });
  const form = page.locator('form[action="/admin/login.php"]');
  await expect(form, 'login form must render').toBeVisible({ timeout: 15000 });
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

// Walk all three steps; resolve when the done report renders. Asserts the
// preview counts real seeded rows (orders ≥ 5 after the re-seed), so the
// wipe below proves something, and that no file failed (a partial wipe
// renders .panic-report-failed — success must not be assumed from the
// report alone).
async function walkWipe(page) {
  await page.goto('/admin/panic.php');
  await expect(stepForm(page, 1)).toBeVisible();
  await stepForm(page, 1).locator('button[type="submit"]').click();

  await expect(stepForm(page, 2)).toBeVisible();
  await stepForm(page, 2).locator('button[type="submit"]').click();

  await expect(page.locator('.panic-counts')).toBeVisible();
  const orders = parseInt(await page.locator('.panic-counts-row span').first().textContent(), 10);
  expect(orders).toBeGreaterThanOrEqual(5);
  await stepForm(page, 3).locator('button[type="submit"]').click();

  await expect(page.locator('.panic-report')).toBeVisible({ timeout: 120_000 });
  expect(await page.locator('.panic-report-failed').count()).toBe(0);
}

test('wipe walks all three steps and logs out', async ({ browser }) => {
  test.setTimeout(180_000);
  reseed();
  const page = await freshPage(browser);
  try {
    await login(page);
    await walkWipe(page);

    // The session is dead: the relogin button lands on the login form,
    // not back inside.
    await page.locator('a[href="/admin/index.php"]').click();
    await expect(page.locator('form[action="/admin/login.php"]')).toBeVisible();
  } finally {
    await closePage(page);
  }
});

test('wiped lists stay empty, then fixtures come back', async ({ browser }) => {
  test.setTimeout(180_000);
  reseed();
  const page = await freshPage(browser);
  try {
    await login(page);
    await walkWipe(page);

    // Users survive the wipe, so login still works — but every evidence
    // table and the backups directory are empty.
    await login(page);
    await page.goto('/admin/backups.php');
    await expect(page.locator('tbody span.token')).toHaveCount(0);
    await page.goto('/admin/orders.php');
    await expect(page.locator('tr', { hasText: 'E2EADMDELIV00001' })).toHaveCount(0);

    // Restore the world for every later file, then prove the app is fully
    // functional again on the recovered rows. The reseed replaces the users
    // row out from under this context's session cookie: drop it, or the
    // next entry lands on a stale-but-cache-valid session (admin_session_
    // status() caches 'ok' 30 s on APCu hosts) instead of the login form.
    // A real user hits the revoked-bounce; a dropped cookie is its
    // deterministic equivalent without the TTL race.
    reseed();
    await page.e2eContext.clearCookies();
    await login(page);
    await expect(page.locator('tr', { hasText: 'E2EADMDELIV00001' })).toHaveCount(1);
  } finally {
    await closePage(page);
  }
});
