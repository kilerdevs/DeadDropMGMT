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
  await page.e2eContext.close();
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

module.exports = { freshPage, closePage, unlockForm, setZoneBbox, zonesSupported };
