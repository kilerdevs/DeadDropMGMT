// Public reveal on self-hosted tiles (Phase 4): a delivered order whose pin
// sits inside a ready zone renders the vendored MapLibre stack with zero
// third-party requests; provider osm keeps the OSM embed. The ready zone
// ('E2E Reveal Zone' + fixture bytes in tiles/) comes from e2e/seed.php; the
// provider flips through the real settings UI and is restored to osm after —
// the suite runs serially on one shared e2e database.
//
// Transport note (same as maps-selfhosted.spec.js): `php -S` cannot answer
// HTTP Range requests, so the zone archive is fulfilled by a Node range
// handler below (206 + Content-Range from the real file bytes). Byte-range
// transport itself was proven against a range-capable server in the P0 spike;
// what this spec pins is the reveal path (covering-zone style + client
// stack) and its network silence.
const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const { freshPage, closePage, unlockForm } = require('../helpers');

const FIXTURE = path.join(__dirname, '..', 'fixtures', 'micro.pmtiles');
const FIXTURE_BYTES = fs.readFileSync(FIXTURE);

async function fulfillRange(route) {
  const header = route.request().headers()['range'];
  const m = /^bytes=(\d*)-(\d*)$/.exec(header || '');
  if (!m) {
    return route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/vnd.pmtiles', 'Accept-Ranges': 'bytes' },
      body: FIXTURE_BYTES,
    });
  }
  const start = m[1] === '' ? Math.max(0, FIXTURE_BYTES.length - parseInt(m[2], 10)) : parseInt(m[1], 10);
  const end = m[2] === '' ? FIXTURE_BYTES.length - 1 : Math.min(parseInt(m[2], 10), FIXTURE_BYTES.length - 1);
  return route.fulfill({
    status: 206,
    headers: {
      'Content-Type': 'application/vnd.pmtiles',
      'Accept-Ranges': 'bytes',
      'Content-Range': `bytes ${start}-${end}/${FIXTURE_BYTES.length}`,
    },
    body: FIXTURE_BYTES.subarray(start, end + 1),
  });
}

async function login(page) {
  await page.goto('/admin/index.php');
  const form = page.locator('form[action="/admin/login.php"]');
  await form.locator('input[name="username"]').fill('e2e_owner');
  await form.locator('input[name="password"]').fill('E2eOwnerPass1!');
  await form.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/admin\/orders\.php/);
}

async function setProvider(page, value) {
  await page.goto('/admin/settings.php');
  await page.locator('#s_map_provider').selectOption(value);
  // Autosave is debounced through the dispatcher; the popup confirms it.
  await expect(page.locator('#save-popup.visible')).toBeVisible({ timeout: 10000 });
  await page.reload();
  await expect(page.locator('#s_map_provider')).toHaveValue(value);
}

async function unlock(page, token, password) {
  await page.goto('/');
  const form = unlockForm(page);
  await form.locator('input[name="order_token"]').fill(token);
  await form.locator('input[name="pickup_password"]').fill(password);
  await form.locator('button[type="submit"]').click();
}

test('selfhosted reveal renders local tiles with zero external requests', async ({ browser }) => {
  const page = await freshPage(browser);
  let external = 0;
  let ranges = 0;
  try {
    await page.e2eContext.route('**/*', (route) => {
      const url = new URL(route.request().url());
      if (url.hostname !== '127.0.0.1') {
        external++;
        return route.abort();
      }
      if (/^\/tiles\/zone_\d+\.pmtiles$/.test(url.pathname)) {
        ranges++;
        return fulfillRange(route);
      }
      return route.continue();
    });

    await login(page);
    await setProvider(page, 'selfhosted');

    // Seeded Warsaw point sits inside the seeded ready zone.
    await unlock(page, 'E2EFLOWDELIVER01', 'E2eReveal1!');
    await expect(page.locator('#reveal-map canvas')).toBeVisible({ timeout: 20000 });
    expect(await page.locator('.map-frame').count()).toBe(0);
    expect(ranges).toBeGreaterThan(0);

    // Nothing ever left the origin: no OSM embed, no tile server, no CDN.
    expect(external).toBe(0);
  } finally {
    // Serial suite, shared database — always hand osm back, even on failure.
    try {
      await setProvider(page, 'osm');
    } catch (e) {
      // The failure report already explains itself; a stuck provider would
      // only cascade into unrelated specs.
    }
    await closePage(page);
  }
});

test('osm provider keeps the OSM embed on the reveal', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await unlock(page, 'E2EFLOWDELIVER01', 'E2eReveal1!');
    await expect(page.locator('.map-frame')).toBeVisible();
    expect(await page.locator('#reveal-map').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});
