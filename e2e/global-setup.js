// Seeds the isolated E2E database before the webServer boots. Fails the run
// loudly when MariaDB/MySQL is unreachable — a green run must never pass
// against an empty or wrong database.
const { spawnSync } = require('node:child_process');

module.exports = async () => {
  const r = spawnSync(process.env.PHP_BINARY || 'php', ['e2e/seed.php'], {
    stdio: 'inherit',
    env: process.env,
  });
  if (r.status !== 0) {
    throw new Error(`e2e/seed.php failed with exit ${r.status}`);
  }
};
