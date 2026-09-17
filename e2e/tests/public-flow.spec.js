// Full public lifecycle in a real browser: lookup, wrong password, unlock,
// single-use reveal, receive confirmation, deletion. The raw-HTTP suite owns
// the adversarial matrix (rotation, replay, budgets); here the happy path
// must work through actual forms and redirects.
const { test, expect } = require('@playwright/test');
const { freshPage, closePage, unlockForm } = require('../helpers');

async function unlock(page, token, password) {
  await page.goto('/');
  const form = unlockForm(page);
  await form.locator('input[name="order_token"]').fill(token);
  await form.locator('input[name="pickup_password"]').fill(password);
  await form.locator('button[type="submit"]').click();
}

test('empty password shows the status badge and asks for the password', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await unlock(page, 'E2EFLOWDELIVER01', '');
    await expect(page.locator('.status-badge.delivered')).toBeVisible();
    await expect(unlockForm(page).locator('input[name="pickup_password"]')).toBeVisible();
    expect(await page.locator('.reveal-value').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});

test('wrong password shows an alert and no reveal', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await unlock(page, 'E2EFLOWDELIVER01', 'nope');
    await expect(page.locator('.alert')).toBeVisible();
    expect(await page.locator('.reveal-value').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});

test('unlock, reveal, confirm receipt, order gone', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await unlock(page, 'E2EFLOWDELIVER02', 'E2eReveal1!');
    await expect(page.locator('text=E2E skrytka')).toBeVisible();
    await expect(page.locator('text=E2E kod do bramy 9876')).toBeVisible();

    // The step rides as a hidden input; scope each form by it, then submit.
    const step1 = page.locator('form', { has: page.locator('input[name="step"][value="1"]') });
    await step1.locator('button[type="submit"]').click();
    const step2 = page.locator('form', { has: page.locator('input[name="step"][value="2"]') });
    await expect(step2).toBeVisible();
    await step2.locator('button[type="submit"]').click();
    await expect(page.locator('.status-badge.delivered')).toBeVisible();

    // The order is deleted: looking it up again answers not-found.
    await unlock(page, 'E2EFLOWDELIVER02', 'E2eReveal1!');
    await expect(page.locator('.alert')).toBeVisible();
    expect(await page.locator('text=E2E skrytka').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});

test('preparing order unlocks to a status card, never a reveal', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await unlock(page, 'E2EFLOWPREP00001', 'E2eReveal1!');
    await expect(page.locator('.status-card')).toBeVisible();
    expect(await page.locator('.reveal-value').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});
