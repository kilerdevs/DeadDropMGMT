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

module.exports = { freshPage, closePage, unlockForm };
