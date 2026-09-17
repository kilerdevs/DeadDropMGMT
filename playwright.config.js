// Playwright drives the app through a real Chromium: the no-JS form paths,
// inline-handler absence in a live DOM, and mid-reveal UI state — everything
// the raw-HTTP PHP suites structurally cannot observe. The server is the same
// `php -S` docroot the PHP suites use, pointed at an isolated database
// (deaddrops_e2e, never deaddrops_test) seeded by e2e/global-setup.js.
const { defineConfig } = require('@playwright/test');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const PORT = Number(process.env.E2E_PORT || 8123);
const sessionDir = path.join(os.tmpdir(), 'ddmgmt_e2e_sessions');
fs.mkdirSync(sessionDir, { recursive: true });

// Same secret-store contract as tests/bootstrap.php: env first, test-only
// defaults last. CI exports the real CI database credentials. NOTE the app
// reads DDMGMT_DB_NAME (bootstrap maps DDMGMT_TEST_DB onto it for the PHP
// suites) — the server needs the real variable, not the test alias.
const dbName = process.env.DDMGMT_DB_NAME || process.env.DDMGMT_TEST_DB || 'deaddrops_e2e';
const dbEnv = {
  DDMGMT_DB_HOST: process.env.DDMGMT_DB_HOST || '127.0.0.1',
  DDMGMT_DB_PORT: process.env.DDMGMT_DB_PORT || '3306',
  DDMGMT_DB_USER: process.env.DDMGMT_DB_USER || 'root',
  DDMGMT_DB_PASS: process.env.DDMGMT_DB_PASS || '',
  DDMGMT_DB_NAME: dbName,
  DDMGMT_TEST_DB: dbName,
  DDMGMT_AES_KEY_HEX:
    process.env.DDMGMT_AES_KEY_HEX ||
    '3f9a1c77e263b7bf1918421d66cbe4e21e011feaac45eae2d1df50a7a28c653b',
};

module.exports = defineConfig({
  testDir: './e2e/tests',
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  globalSetup: require.resolve('./e2e/global-setup.js'),
  webServer: {
    command: `"${process.env.PHP_BINARY || 'php'}" -d session.save_path="${sessionDir}" -S 127.0.0.1:${PORT} -t .`,
    url: `http://127.0.0.1:${PORT}/healthz.php`,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    env: dbEnv,
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
