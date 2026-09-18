// Admin authentication through real forms: rejection, login, order edit with
// the CSP-proof extend form (real POST buttons, no onclick), and logout.
const { test, expect } = require('@playwright/test');
const { freshPage, closePage } = require('../helpers');

function loginForm(page) {
  return page.locator('form[action="/admin/login.php"]');
}

async function login(page, username, password) {
  await page.goto('/admin/index.php');
  const form = loginForm(page);
  await form.locator('input[name="username"]').fill(username);
  await form.locator('input[name="password"]').fill(password);
  await form.locator('button[type="submit"]').click();
}

test('wrong credentials stay on the login page with an error', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await login(page, 'e2e_owner', 'WrongPass1!');
    await expect(page).toHaveURL(/admin\/index\.php/);
    expect((await page.content()).length).toBeGreaterThan(0);
    expect(await page.locator('form[action="/admin/login.php"]').count()).toBe(1);
  } finally {
    await closePage(page);
  }
});

test('login, edit order, CSP-proof extend form, logout', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await login(page, 'e2e_owner', 'E2eOwnerPass1!');
    await expect(page).toHaveURL(/admin\/orders\.php/);

    // Open the dedicated delivered order (E2EADMDELIV00001 stays delivered:
    // no other spec touches it): only delivered orders render extend forms.
    await page.locator('tr', { hasText: 'E2EADMDELIV00001' }).locator('a.action-btn').click();
    await expect(page).toHaveURL(/admin\/edit\.php/);
    // The right order, then the form: the token pin catches a wrong-row
    // click, the retrying visibility absorbs loaded-server slowness.
    await expect(page.locator('span.token').first()).toContainText('E2EADMDELIV00001');
    // CSP-proof extend path: real POST forms (one per action on the page),
    // zero inline handlers anywhere.
    const extend = page.locator('form.extend-form');
    await expect(extend.first()).toBeVisible();
    expect(await extend.count()).toBeGreaterThan(0);
    expect(await page.locator('[onclick]').count()).toBe(0);

    const logout = page.locator('form[action="/admin/logout.php"]');
    await logout.locator('button[type="submit"]').click();
    await expect(page).toHaveURL(/admin\/index\.php/);
  } finally {
    await closePage(page);
  }
});

// The server rotates the session CSRF token every time a request verifies it,
// so the copy rendered into a page goes stale as soon as anything else on that
// page (an autosave, the zones poll) has run. The sidebar language switch used
// to alert "CSRF" and logout silently did nothing after that; both now take the
// live token from /admin/csrf_token.php.
test('language switch and logout survive a stale page token', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    let dialogs = 0;
    page.on('dialog', async (d) => {
      dialogs++;
      await d.dismiss();
    });
    await login(page, 'e2e_owner', 'E2eOwnerPass1!');
    await expect(page).toHaveURL(/admin\/orders\.php/);
    await page.goto('/admin/settings.php');

    // Burn the token this page was rendered with: one verified request from the
    // page. The live token comes from the server (the page's own zones poll may
    // already have rotated the rendered one, which would make this a 403 and
    // the test about something else) — verifying it rotates it again, so every
    // copy rendered into the page is stale afterwards, whatever ran before.
    const burn = () => page.evaluate(async () => {
      const live = await (await fetch('/admin/csrf_token.php', { credentials: 'same-origin' })).json();
      const fd = new FormData();
      fd.append('csrf_token', live.csrf);
      fd.append('action', 'status');
      const r = await fetch('/admin/maps_action.php', { method: 'POST', body: fd });
      return r.ok;
    });
    expect(await burn()).toBe(true);

    await page.selectOption('#sidebar-lang-select', 'de');
    await expect(page.locator('html')).toHaveAttribute('lang', 'de', { timeout: 15000 });
    expect(dialogs).toBe(0);

    // Back to English so later specs keep their expectations.
    await page.selectOption('#sidebar-lang-select', 'en');
    await expect(page.locator('html')).toHaveAttribute('lang', 'en', { timeout: 15000 });
    expect(dialogs).toBe(0);

    // Logout after another stale-making request must really end the session.
    expect(await burn()).toBe(true);
    await page.locator('form[action="/admin/logout.php"] button[type="submit"]').click();
    await expect(page).toHaveURL(/admin\/index\.php/);
    await page.goto('/admin/orders.php');
    await expect(page).toHaveURL(/admin\/index\.php/);
  } finally {
    await closePage(page);
  }
});
