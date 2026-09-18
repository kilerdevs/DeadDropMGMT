// Self-hosted maps (Phase 1): provider switch through the real settings UI,
// MapLibre render against the committed fixture archive, click-to-pin, and
// a machine-checked proof of zero third-party requests.
//
// Transport note: `php -S` cannot answer HTTP Range requests, so the fixture
// archive is fulfilled by a Node range handler below (206 + Content-Range
// from the real file bytes). Byte-range transport itself was proven against
// a range-capable server in the P0 spike; what this spec pins is the client
// stack (MapLibre + pmtiles.js + style + picker) and its network silence.
const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const { freshPage, closePage } = require('../helpers');

const FIXTURE = path.join(__dirname, '..', 'fixtures', 'micro.pmtiles');
const FIXTURE_BYTES = fs.readFileSync(FIXTURE);

function stubStyle() {
  const layers = [
    { id: 'background', type: 'background', paint: { 'background-color': '#111418' } },
  ];
  for (const l of ['earth', 'water', 'roads', 'buildings']) {
    layers.push({
      id: l, type: l === 'roads' ? 'line' : 'fill',
      source: 'fixture', 'source-layer': l,
      paint: l === 'roads'
        ? { 'line-color': '#5a636e' }
        : { 'fill-color': '#1a1e24' },
    });
  }
  return {
    version: 8,
    sources: {
      fixture: {
        type: 'vector',
        url: 'pmtiles:///e2e/fixtures/micro.pmtiles',
        maxzoom: 10,
        attribution: '© OpenStreetMap contributors',
      },
    },
    layers,
  };
}

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

test('selfhosted provider renders the fixture map with zero external requests', async ({ browser }) => {
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
      if (url.pathname === '/e2e/fixtures/micro.pmtiles') {
        ranges++;
        return fulfillRange(route);
      }
      if (url.pathname === '/tiles/style.php') {
        return route.fulfill({ json: stubStyle() });
      }
      return route.continue();
    });

    await login(page);
    await setProvider(page, 'selfhosted');

    await page.goto('/admin/new_order.php');
    // Self-hosted stack in, Leaflet out.
    expect(await page.locator('script[src="/maplibre/maplibre-gl.js"]').count()).toBe(1);
    expect(await page.locator('script[src="/admin/vendor/leaflet/leaflet.js"]').count()).toBe(0);

    // The map canvas appears once the style + first tiles resolve.
    await expect(page.locator('#map-picker canvas')).toBeVisible({ timeout: 20000 });
    expect(ranges).toBeGreaterThan(0);

    // Click-to-pin fills the coordinate inputs (same contract as Leaflet).
    await page.locator('#map-picker').click({ position: { x: 200, y: 150 } });
    await expect(page.locator('#lat')).not.toHaveValue('', { timeout: 5000 });
    await expect(page.locator('#coords-display')).toContainText('Pin:');

    // Nothing ever left the origin: no tile server, no font host, no CDN.
    expect(external).toBe(0);
  } finally {
    await closePage(page);
  }
});

test('empty zones render the map chrome with a no-zones overlay', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await login(page);
    await setProvider(page, 'selfhosted');

    // Real /tiles/style.php: no zones in the e2e database, so no sources.
    await page.goto('/admin/new_order.php');
    await expect(page.locator('#map-picker canvas')).toBeVisible({ timeout: 20000 });
    await expect(page.locator('.map-empty-overlay')).toBeVisible();
  } finally {
    await closePage(page);
  }
});

test('provider restores to osm (default stack unchanged)', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await login(page);
    await setProvider(page, 'osm');
    await page.goto('/admin/new_order.php');
    expect(await page.locator('script[src="/admin/vendor/leaflet/leaflet.js"]').count()).toBe(1);
    expect(await page.locator('script[src="/maplibre/maplibre-gl.js"]').count()).toBe(0);
  } finally {
    await closePage(page);
  }
});
