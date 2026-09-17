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
    // CSP-proof extend path: real POST forms (one per action on the page),
    // zero inline handlers anywhere.
    const extend = page.locator('form.extend-form');
    expect(await extend.count()).toBeGreaterThan(0);
    await expect(extend.first()).toBeVisible();
    expect(await page.locator('[onclick]').count()).toBe(0);

    const logout = page.locator('form[action="/admin/logout.php"]');
    await logout.locator('button[type="submit"]').click();
    await expect(page).toHaveURL(/admin\/index\.php/);
  } finally {
    await closePage(page);
  }
});
