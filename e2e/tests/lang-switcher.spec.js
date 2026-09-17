// The language switcher through a real browser: the no-JS submit path (the
// 2026-09 audit found the select dead without JavaScript), persistence, the
// unknown-code guard, handler absence in a live DOM, and the mid-reveal hide.
const { test, expect } = require('@playwright/test');
const { freshPage, closePage, unlockForm } = require('../helpers');

test('no-JS: Apply button switches language and it persists', async ({ browser }) => {
  const page = await freshPage(browser, { javaScriptEnabled: false });
  try {
    await page.goto('/');
    const switcher = page.locator('form.lang-switch');
    await expect(switcher).toBeVisible();
    // The select auto-submit is gone by design — the button is the path.
    await switcher.locator('select#lang').selectOption('de');
    await switcher.locator('button[type="submit"]').click();
    await expect(page.locator('h1')).toHaveText('Sendung verfolgen');
    await expect(page).toHaveURL(/lang=de/);

    await page.reload();
    await expect(page.locator('h1')).toHaveText('Sendung verfolgen');

    const cookie = (await page.context().cookies()).find((c) => c.name === 'ddmgmt_lang');
    expect(cookie && cookie.value).toBe('de');
    expect(cookie.expires).toBeGreaterThan(Date.now() / 1000 + 300 * 24 * 3600);
  } finally {
    await closePage(page);
  }
});

test('with JS: switching works identically', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await page.goto('/');
    const switcher = page.locator('form.lang-switch');
    await switcher.locator('select#lang').selectOption('de');
    await switcher.locator('button[type="submit"]').click();
    await expect(page.locator('h1')).toHaveText('Sendung verfolgen');
  } finally {
    await closePage(page);
  }
});

test('unknown language code is ignored', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await page.goto('/?lang=xx');
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(page.locator('h1')).toHaveText('Track a delivery');
  } finally {
    await closePage(page);
  }
});

test('no inline event handlers in the live DOM', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    for (const url of ['/', '/receive.php', '/admin/index.php']) {
      await page.goto(url);
      expect(await page.locator('[onchange],[onclick],[onsubmit],[onload],[onerror]').count()).toBe(0);
    }
  } finally {
    await closePage(page);
  }
});

test('switcher hides mid-reveal and returns once the reveal is consumed', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await page.goto('/');
    const form = unlockForm(page);
    await form.locator('input[name="order_token"]').fill('E2ELANGDELIVER01');
    await form.locator('input[name="pickup_password"]').fill('E2eReveal1!');
    await form.locator('button[type="submit"]').click();
    // Unlock answers with a PRG redirect; the reveal lands on the follow-up GET.
    await expect(page.locator('text=E2E skrytka')).toBeVisible();
    expect(await page.locator('form.lang-switch').count()).toBe(0);

    // The reveal is single-use session data: a reload consumes it, and the
    // switcher comes back instead of silently discarding anything.
    await page.reload();
    expect(await page.locator('text=E2E skrytka').count()).toBe(0);
    await expect(page.locator('form.lang-switch')).toBeVisible();
  } finally {
    await closePage(page);
  }
});
