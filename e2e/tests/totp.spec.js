// TOTP enrollment through the real 2fa.php flow: a wrong code changes
// nothing, the right code — computed from the enrolled secret exactly like
// a phone authenticator — enables, the next login is challenged at
// verify_2fa.php, and disabling restores clean logins. Each test reseeds
// first (e2e_owner starts with 2FA off) and the file ends with 2FA off, so
// later files can log in normally.
const { test, expect } = require('@playwright/test');
const { freshPage, closePage, reseed, totpCode } = require('../helpers');

function loginForm(page) {
  return page.locator('form[action="/admin/login.php"]');
}

// The enable/disable forms share one action: scope by the hidden field.
function twofaForm(page, action) {
  return page.locator('form[action="/admin/2fa.php"]', {
    has: page.locator(`input[name="action"][value="${action}"]`),
  });
}

async function passwordLogin(page) {
  await page.goto('/admin/index.php');
  // A pre-existing session here means 2FA state leaked between tests —
  // fail loudly instead of hanging on a form that will never render.
  // (No orders-URL check: after enroll the password step lands on the
  // challenge, which the caller asserts.)
  const form = loginForm(page);
  await expect(form, 'login form must render').toBeVisible({ timeout: 15000 });
  await form.locator('input[name="username"]').fill('e2e_owner');
  await form.locator('input[name="password"]').fill('E2eOwnerPass1!');
  await form.locator('button[type="submit"]').click();
}

// The secret renders chunked for readability ("ABCD EFGH ..."): strip the
// whitespace exactly like the page's own copy button does.
async function readSecret(page) {
  const raw = await page.locator('#totp-secret').textContent();
  const secret = raw.replace(/\s+/g, '');
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  return secret;
}

// A code guaranteed to differ from the given valid one.
function wrongCode(right) {
  return right === '000000' ? '000001' : '000000';
}

// Codes are single-use and windowed: always compute fresh, right before the
// fill, never reuse a value across submits.
async function submitCode(form, secret) {
  await form.locator('input[name="code"]').fill(totpCode(secret));
  await form.locator('button[type="submit"]').click();
}

test('wrong code refuses, right code enables', async ({ browser }) => {
  test.setTimeout(60_000);
  reseed();
  const page = await freshPage(browser);
  try {
    await passwordLogin(page);
    await expect(page).toHaveURL(/admin\/orders\.php/);
    await page.goto('/admin/2fa.php');
    await expect(twofaForm(page, 'enable')).toBeVisible();
    const secret = await readSecret(page);

    // A wrong code changes nothing: an error flash, and the enable form is
    // still the enable form (no disable form appears).
    const enable = twofaForm(page, 'enable');
    await enable.locator('input[name="code"]').fill(wrongCode(totpCode(secret)));
    await enable.locator('button[type="submit"]').click();
    await expect(page.locator('.flash:not(.ok)')).toBeVisible();
    expect(await twofaForm(page, 'enable').count()).toBe(1);
    expect(await twofaForm(page, 'disable').count()).toBe(0);

    // The right code enables: the disable form replaces the enable one.
    await submitCode(twofaForm(page, 'enable'), secret);
    await expect(page.locator('.flash.ok')).toBeVisible();
    await expect(twofaForm(page, 'disable')).toBeVisible();
  } finally {
    await closePage(page);
  }
});

test('challenge gates login, disable restores clean login', async ({ browser }) => {
  test.setTimeout(60_000);
  reseed();
  let secret = '';
  const page = await freshPage(browser);
  try {
    // Enroll first: this test owns its enabled state end to end.
    await passwordLogin(page);
    await expect(page).toHaveURL(/admin\/orders\.php/);
    await page.goto('/admin/2fa.php');
    secret = await readSecret(page);
    await submitCode(twofaForm(page, 'enable'), secret);
    await expect(twofaForm(page, 'disable')).toBeVisible();
  } finally {
    await closePage(page);
  }

  // A session WITHOUT the login: password alone must land on the
  // challenge, never inside.
  const attacker = await freshPage(browser);
  try {
    await passwordLogin(attacker);
    await expect(attacker).toHaveURL(/admin\/verify_2fa\.php/);
    const challenge = attacker.locator('form[action="/admin/verify_2fa.php"]');
    // Two submits share the form (verify + POST-only logout-as-cancel):
    // the verifier is the one without a formaction override.
    const verify = challenge.locator('button[type="submit"]:not([formaction])');
    await expect(challenge).toBeVisible();

    // A wrong code stays on the challenge with an alert, not inside.
    await challenge.locator('input[name="code"]').fill(wrongCode(totpCode(secret)));
    await verify.click();
    await expect(attacker.locator('.alert')).toBeVisible();
    await expect(attacker).toHaveURL(/admin\/verify_2fa\.php/);

    // The right code completes the login.
    await challenge.locator('input[name="code"]').fill(totpCode(secret));
    await verify.click();
    await expect(attacker).toHaveURL(/admin\/orders\.php/);

    // Disabling (which itself demands a fresh valid code) restores the
    // account to no-2FA: the enable form is back.
    await attacker.goto('/admin/2fa.php');
    await expect(twofaForm(attacker, 'disable')).toBeVisible();
    await submitCode(twofaForm(attacker, 'disable'), secret);
    await expect(attacker.locator('.flash.ok')).toBeVisible();
    await expect(twofaForm(attacker, 'enable')).toBeVisible();
  } finally {
    await closePage(attacker);
  }

  // And a clean login afterwards meets no challenge at all.
  const clean = await freshPage(browser);
  try {
    await passwordLogin(clean);
    await expect(clean).toHaveURL(/admin\/orders\.php/);
  } finally {
    await closePage(clean);
  }
});
