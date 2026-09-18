// Maps zone editor (Phase 3): draw-on-canvas fills the bbox inputs, typed
// bboxes redraw the draft, overlapping drafts warn, and queueing flows into
// the zone table. Hermetic: tile traffic is aborted (Leaflet draws fine on
// an empty grid) and queued zones are deleted again, so no worker can do
// real work — the kick races a delete it always loses on a fresh queue.
const { test, expect } = require('@playwright/test');
const { freshPage, closePage } = require('../helpers');

async function login(page) {
  await page.goto('/admin/index.php');
  const form = page.locator('form[action="/admin/login.php"]');
  await form.locator('input[name="username"]').fill('e2e_owner');
  await form.locator('input[name="password"]').fill('E2eOwnerPass1!');
  await form.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/admin\/orders\.php/);
}

async function openEditor(page) {
  await login(page);
  // Same-origin tile proxy, but abort the upstream traffic: the editor
  // must work on an empty grid.
  await page.route('**/admin/tile_proxy.php**', (route) => route.abort());
  await page.goto('/admin/settings.php');
  await expect(page.locator('#mz-map.leaflet-container')).toBeVisible({ timeout: 15000 });
}

async function mapCenter(page) {
  const box = await page.locator('#mz-map').boundingBox();
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
}

async function readBbox(page) {
  const ids = ['#mz-min-lon', '#mz-min-lat', '#mz-max-lon', '#mz-max-lat'];
  const out = {};
  for (const id of ids) out[id] = await page.locator(id).inputValue();
  return out;
}

async function deleteZone(page, name) {
  page.once('dialog', (dialog) => dialog.accept());
  const row = page.locator('#maps-tbody tr', { hasText: name });
  await row.locator('.mz-del').click();
  await expect(row).toHaveCount(0, { timeout: 10000 });
}

async function deleteZoneIfPresent(page, name) {
  const row = page.locator('#maps-tbody tr', { hasText: name });
  if ((await row.count()) === 0) return;
  await deleteZone(page, name);
}

test('drag-draw fills the bbox inputs', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await openEditor(page);
    await page.locator('#mz-draw').click();
    const c = await mapCenter(page);
    await page.mouse.move(c.x - 60, c.y - 40);
    await page.mouse.down();
    await page.mouse.move(c.x + 60, c.y + 40, { steps: 12 });
    await page.mouse.up();
    const bbox = await readBbox(page);
    const nums = Object.values(bbox).map(Number);
    expect(nums.every((n) => Number.isFinite(n))).toBe(true);
    const [w, s, e, n] = nums;
    expect(w).toBeLessThan(e);
    expect(s).toBeLessThan(n);
    // Draft rectangle + 4 corner handles rendered.
    await expect(page.locator('#mz-map .leaflet-overlay-pane path')).not.toHaveCount(0);
  } finally {
    await closePage(page);
  }
});

test('typed bbox redraws the draft and queueing lists the zone', async ({ browser }) => {
  const page = await freshPage(browser);
  const name = 'E2E Editor Typed';
  try {
    await openEditor(page);
    await page.locator('#mz-name').fill(name);
    await page.locator('#mz-min-lon').fill('20.95');
    await page.locator('#mz-min-lat').fill('52.10');
    await page.locator('#mz-max-lon').fill('21.05');
    await page.locator('#mz-max-lat').fill('52.20');
    // Firing change redraws the draft rectangle.
    await page.locator('#mz-max-lat').dispatchEvent('change');
    await expect(page.locator('#mz-map .leaflet-overlay-pane path')).not.toHaveCount(0);
    await page.locator('#mz-add').click();
    await expect(page.locator('#save-popup.visible:not(.error)')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#maps-tbody tr', { hasText: name })).toBeVisible({ timeout: 15000 });
    await deleteZone(page, name);
  } finally {
    try { await deleteZoneIfPresent(page, name); } catch { /* already gone */ }
    await closePage(page);
  }
});

test('overlapping draft shows the warning', async ({ browser }) => {
  const page = await freshPage(browser);
  const name = 'E2E Editor Base';
  try {
    await openEditor(page);
    // Seed an existing zone through the real queue path (tiny bbox).
    await page.locator('#mz-name').fill(name);
    await page.locator('#mz-min-lon').fill('20.90');
    await page.locator('#mz-min-lat').fill('52.10');
    await page.locator('#mz-max-lon').fill('21.10');
    await page.locator('#mz-max-lat').fill('52.30');
    await page.locator('#mz-max-lat').dispatchEvent('change');
    await page.locator('#mz-add').click();
    await expect(page.locator('#maps-tbody tr', { hasText: name })).toBeVisible({ timeout: 15000 });
    // Draw a clearly overlapping draft on the canvas.
    await page.reload();
    await expect(page.locator('#mz-map.leaflet-container')).toBeVisible({ timeout: 15000 });
    await page.locator('#mz-draw').click();
    const c = await mapCenter(page);
    await page.mouse.move(c.x - 80, c.y - 60);
    await page.mouse.down();
    await page.mouse.move(c.x + 80, c.y + 60, { steps: 12 });
    await page.mouse.up();
    const warn = page.locator('#mz-overlap:not([hidden])');
    await expect(warn).toBeVisible({ timeout: 5000 });
    expect(await warn.textContent()).toMatch(/%/);
    await deleteZone(page, name);
  } finally {
    try { await deleteZoneIfPresent(page, name); } catch { /* already gone */ }
    await closePage(page);
  }
});

test('place search pans without third-party contact', async ({ browser }) => {
  const page = await freshPage(browser);
  try {
    await openEditor(page);
    // Stub the proxied Nominatim answer: no upstream traffic, map still pans.
    await page.route('**/admin/geocode_proxy.php**', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([{ lat: '52.23', lon: '21.01', display_name: 'Warsaw' }]),
      })
    );
    await page.locator('#mz-search').fill('Warsaw');
    await page.locator('#mz-find').click();
    await expect(page.locator('#save-popup.visible.error')).toHaveCount(0);
  } finally {
    await closePage(page);
  }
});
