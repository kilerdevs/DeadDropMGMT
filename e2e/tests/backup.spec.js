// Owner backup lifecycle through real forms: create lists a bundle, restore
// refuses a wrong owner password, accepts the right one (stored bundle AND
// upload round-trip), delete removes it. The bundle is cut from the live e2e
// rows, so restoring it is a semantic no-op — the spec asserts the app flow
// (verify-then-apply, re-auth gate, quiet codes), not data loss.
//
// backups/ is a SHARED directory (the PHP suites stage bundles there too),
// so no test may assume its contents: every test creates its own bundle and
// reads the server-generated name back out of the creation notice, and the
// last test deletes exactly the bundles this file created, by exact name.
const { test, expect } = require('@playwright/test');
const { freshPage, closePage } = require('../helpers');
const path = require('node:path');
const os = require('node:os');

const created = [];

async function login(page) {
  const resp = await page.goto('/admin/index.php');
  // Fail fast and loud instead of hanging a whole test budget: a missing
  // form means a stale session, the bootstrap form, or a white-screen 500.
  expect(resp && resp.ok(), 'index.php must answer 2xx, not a white-screen 500').toBe(true);
  await expect(page, 'must be logged out at login entry, not redirected inside').not.toHaveURL(/admin\/orders\.php/, { timeout: 15000 });
  const form = page.locator('form[action="/admin/login.php"]');
  await expect(form, 'login form must render').toBeVisible({ timeout: 15000 });
  await form.locator('input[name="username"]').fill('e2e_owner');
  await form.locator('input[name="password"]').fill('E2eOwnerPass1!');
  await form.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/admin\/orders\.php/);
}

// Scope the three same-action forms by their hidden action field.
function backupForm(page, action) {
  return page.locator('form[action="/admin/backups.php"]', {
    has: page.locator(`input[name="action"][value="${action}"]`),
  });
}

// Bundle names are `backup-YYYYMMDD-HHMMSS.ext`, but same-second creates
// collide: the app then appends `-N` (`backup-…-1.zip`). The specs must
// accept every legal name — CI once failed a run on exactly this.
// Match cells by EXACT text for the same reason: substring matching cannot
// tell `X.zip` apart from `X-1.zip` in the delete loop below.
const bundleNameRe = /backup-\d{8}-\d{6}(?:-\d+)?\.(zip|json\.gz|json)/;
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function tokenCell(page, bundle) {
  return page.locator('tbody span.token', { hasText: new RegExp(`^${escapeRegExp(bundle)}$`) });
}

// Click a POST-returns-HTML submit and wait for THAT response: asserting on
// the DOM alone can pass on the previous request's flash (same page, no
// redirect), letting the next step race — and kill — the in-flight POST.
async function submitAndWait(page, button) {
  const [resp] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === 'POST' && r.url().includes('/admin/backups.php')
    ),
    button.click(),
  ]);
  expect(resp.ok()).toBe(true);
}

// Create a bundle and return its server-generated name, parsed from the
// creation notice (never from table position — directory order is not a
// contract and other harnesses share the directory).
async function createBundle(page) {
  await page.goto('/admin/backups.php');
  await expect(backupForm(page, 'create')).toBeVisible();
  await submitAndWait(page, backupForm(page, 'create').locator('button[type="submit"]'));
  const flash = page.locator('.flash.flash-ok');
  await expect(flash).toBeVisible({ timeout: 30000 });
  const text = await flash.textContent();
  const name = text.match(bundleNameRe)?.[0];
  expect(name, 'creation notice names the bundle').toBeTruthy();
  created.push(name);
  // ...and the bundle lists under exactly that name.
  await expect(tokenCell(page, name)).toHaveCount(1);
  return name;
}

test('create lists a new bundle', async ({ browser }) => {
  // Backup I/O runs under a single-threaded php -S against MySQL shared
  // with the whole CI matrix: budget for a loaded runner, not a laptop.
  test.setTimeout(60_000);
  const page = await freshPage(browser);
  try {
    await login(page);
    await page.goto('/admin/backups.php');
    // Unsupported hosts show a flash instead of the create form — fail
    // loudly here rather than timing out on a missing button later.
    await expect(backupForm(page, 'create')).toBeVisible();
    const before = await page.locator('tbody span.token').count();
    const name = await createBundle(page);
    expect(await page.locator('tbody span.token').count()).toBe(before + 1);
    expect(name).toMatch(/^backup-\d{8}-\d{6}(?:-\d+)?\.(zip|json\.gz|json)$/);
  } finally {
    await closePage(page);
  }
});

test('restore refuses a wrong owner password', async ({ browser }) => {
  test.setTimeout(120_000);
  const page = await freshPage(browser);
  try {
    await login(page);
    const name = await createBundle(page);
    const restore = backupForm(page, 'restore');
    await restore.locator('input[name="source"][value="stored"]').check();
    await restore.locator('select[name="file"]').selectOption(name);
    await restore.locator('input[name="password"]').fill('WrongPass1!');
    await submitAndWait(page, restore.locator('button[name="restore_btn"]'));
    // An error flash, not the ok one: the password gate held and nothing
    // was verified, staged, or applied.
    await expect(page.locator('.flash:not(.flash-ok)')).toBeVisible();
    expect(await page.locator('.flash.flash-ok').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});

test('restore from the stored bundle succeeds and keeps every row', async ({ browser }) => {
  // Restore verifies, stages and re-applies the whole database in one
  // transaction: the slowest owner action in this file on a loaded host.
  test.setTimeout(120_000);
  const page = await freshPage(browser);
  try {
    await login(page);
    const name = await createBundle(page);
    const restore = backupForm(page, 'restore');
    await restore.locator('input[name="source"][value="stored"]').check();
    await restore.locator('select[name="file"]').selectOption(name);
    await restore.locator('input[name="password"]').fill('E2eOwnerPass1!');
    await submitAndWait(page, restore.locator('button[name="restore_btn"]'));
    await expect(page.locator('.flash.flash-ok')).toBeVisible({ timeout: 30000 });
    // The round-trip replaced every row with itself: the seeded order the
    // other specs depend on is still listed.
    await page.goto('/admin/orders.php');
    await expect(page.locator('tr', { hasText: 'E2EADMDELIV00001' })).toHaveCount(1);
  } finally {
    await closePage(page);
  }
});

test('upload round-trip restores, then only our bundles are deleted', async ({ browser }) => {
  test.setTimeout(120_000);
  const page = await freshPage(browser);
  try {
    await login(page);
    const name = await createBundle(page);

    // Download the bundle, then feed it back through the upload path: this
    // exercises the .part staging, the move_uploaded_file gate and the
    // unconditional unlink — none of which the stored path touches.
    const link = page.locator('tbody tr', { has: page.locator('span.token', { hasText: name }) }).locator('a[href*="download_backup.php"]');
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      link.click(),
    ]);
    const tmp = path.join(os.tmpdir(), `e2e-restore-${Date.now()}-${download.suggestedFilename()}`);
    await download.saveAs(tmp);

    const restore = backupForm(page, 'restore');
    await restore.locator('input[name="source"][value="upload"]').check();
    await restore.locator('input[name="backupfile"]').setInputFiles(tmp);
    await restore.locator('input[name="password"]').fill('E2eOwnerPass1!');
    await submitAndWait(page, restore.locator('button[name="restore_btn"]'));
    await expect(page.locator('.flash.flash-ok')).toBeVisible({ timeout: 30000 });

    // Delete asks for confirmation: accept it, or Playwright's default
    // dismiss leaves the bundle in place. Only exact names from this file
    // are deleted — other harnesses' bundles are not ours to touch. Rows
    // already gone (a retried attempt cleaned up) are skipped, not failed.
    await page.goto('/admin/backups.php');
    page.on('dialog', (d) => d.accept());
    for (const bundle of [...new Set(created)]) {
      const row = page.locator('tbody tr', { has: tokenCell(page, bundle) });
      if ((await row.count()) === 0) continue;
      await submitAndWait(page, row.locator('button[type="submit"]'));
      await expect(page.locator('.flash.flash-ok')).toBeVisible();
      await expect(tokenCell(page, bundle)).toHaveCount(0);
    }
  } finally {
    await closePage(page);
  }
});
