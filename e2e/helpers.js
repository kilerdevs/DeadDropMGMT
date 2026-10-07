// Shared browser helpers. Every test gets its own context: PHP sessions and
// single-use states (reveal, CSRF rotation) must never leak between tests,
// even inside one file.
async function freshPage(browser, options = {}) {
  const context = await browser.newContext(options);
  const page = await context.newPage();
  // NOTE: `page.context` is a built-in getter-only method — never shadow it.
  page.e2eContext = context;
  return page;
}

async function closePage(page) {
  // Tolerant teardown: on loaded CI runners Chromium occasionally drops a
  // context (crash/OOM) after the test body already passed — failing the
  // test on cleanup then hides a green result and buys nothing (the browser
  // exits with the suite; contexts are per-test). Body failures are
  // recorded before finally runs, so swallowing here never masks them.
  try {
    await page.e2eContext.close();
  } catch (e) {
    // Context already gone — nothing left to clean up.
  }
}

// The unlock form on / is one of two GET forms — scope by its token field.
function unlockForm(page) {
  return page.locator('form', { has: page.locator('input[name="order_token"]') });
}

// The zone bbox inputs are hidden (the rectangle is drawn on the map). Specs
// that need an exact rectangle set the values directly and fire change —
// what a draw leaves behind — since Playwright cannot fill hidden inputs.
async function setZoneBbox(page, minLon, minLat, maxLon, maxLat, { fireChange = true } = {}) {
  await page.evaluate(([w, s, e, n, fire]) => {
    document.getElementById('mz-min-lon').value = w;
    document.getElementById('mz-min-lat').value = s;
    document.getElementById('mz-max-lon').value = e;
    document.getElementById('mz-max-lat').value = n;
    if (fire) document.getElementById('mz-max-lat').dispatchEvent(new Event('change'));
  }, [minLon, minLat, maxLon, maxLat, fireChange]);
}

// Zone downloads need Linux + exec + cURL (maps_downloads_supported): on
// hosts without them the queue button renders disabled and the actions
// refuse, so queue-dependent specs skip instead of timing out on the
// disabled control.
async function zonesSupported(page) {
  return (await page.locator('#maps-unsupported').count()) === 0;
}

module.exports = { freshPage, closePage, unlockForm, setZoneBbox, zonesSupported, reseed, totpCode };

// Destructive specs (panic wipe, 2FA enroll) re-run the fixtures from inside
// the spec file: global-setup runs once per suite, so without this a wipe
// would starve every later file (workers:1 runs files serially, but order
// alone cannot save a CI retry — the re-seed makes each file hermetic).
// Same mechanism as global-setup: same machine, same env, repo-root paths
// resolved from this file so `playwright test` works from any cwd.
function reseed() {
  const { spawnSync } = require('node:child_process');
  const path = require('node:path');
  const r = spawnSync(process.env.PHP_BINARY || 'php', [path.join(__dirname, 'seed.php')], {
    stdio: 'inherit',
    env: process.env,
  });
  if (r.status !== 0) {
    throw new Error(`e2e/seed.php failed with exit ${r.status}`);
  }
}

// RFC 6238 TOTP (SHA-1, 30 s, 6 digits) mirroring includes/totp.php, so specs
// can complete enrollment without an authenticator app. The server accepts
// ±1 step, so computing at submit time is always in-window; no window logic
// here — generating a code is not verifying one.
function totpCode(secretB32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(secretB32).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const c of clean) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const key = Buffer.from(bytes);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hmac = require('node:crypto').createHmac('sha1', key).update(msg).digest();
  const offset = hmac[19] & 0x0f;
  // 0x7F mask keeps the top bit clear: max 0x7FFFFFFF, safe in 32-bit ops.
  const part = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(part % 1000000).padStart(6, '0');
}
