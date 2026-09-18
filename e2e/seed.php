<?php
declare(strict_types=1);

// (Re)creates the browser-test database and its fixtures. Isolated from the
// PHP suites by name (deaddrops_e2e, never deaddrops_test): the two harnesses
// may run side by side, and neither may observe the other's rows.
// Idempotent — DELETEs its own rows, then re-inserts.

if (getenv('DDMGMT_TEST_DB') === false) {
    putenv('DDMGMT_TEST_DB=deaddrops_e2e');
}
require_once __DIR__ . '/../tests/bootstrap.php';
require __DIR__ . '/../tests/schema_loader.php';

$db = get_db();

// Generous budgets: the browser specs assert happy paths and validation
// errors — the limiter's math belongs to the PHP suites (RateLimitTest).
set_setting('rate_limit_max', '1000');
set_setting('rate_limit_window_min', '60');
set_setting('default_lang', 'en');

$db->prepare("DELETE FROM users WHERE username = 'e2e_owner'")->execute();
$db->prepare("DELETE FROM orders WHERE order_token LIKE 'E2E%'")->execute();
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");

$db->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
    ->execute(['e2e_owner', password_hash('E2eOwnerPass1!', PASSWORD_BCRYPT), 'owner']);

$enc = encrypt_location_data([
    'text'         => 'E2E skrytka pod czwartą ławą',
    'lat'          => 52.2297,
    'lng'          => 21.0122,
    'instructions' => 'E2E kod do bramy 9876',
]);
$ins = $db->prepare(
    'INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status, delivered_at, expires_at, notes)
     VALUES (?, ?, ?, ?, ?, ?, NOW() + INTERVAL 24 HOUR, ?)'
);
$pw = password_hash('E2eReveal1!', PASSWORD_BCRYPT);
$ins->execute(['E2ELANGDELIVER01', $pw, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), 'E2E notka']);
$ins->execute(['E2EFLOWDELIVER01', $pw, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);
$ins->execute(['E2EFLOWDELIVER02', $pw, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);
$ins->execute(['E2EFLOWPREP00001', $pw, $enc['ciphertext'], $enc['iv'], 'preparing', null, '']);
$ins->execute(['E2EADMDELIV00001', $pw, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);

// Self-hosted reveal fixture (Phase 4): a ready zone covering the seeded
// Warsaw point (52.2297, 21.0122), backed by the committed micro.pmtiles
// build (bbox 20.95,52.20 → 21.10,52.28 per e2e/fixtures/README.md). The id
// varies per run, so stale zone files are swept before the fixture is
// copied under its fresh name. maps-zones.spec.js accounts for this row —
// it asserts the bad zone was NOT queued, not an empty table.
$db->prepare("DELETE FROM map_zones WHERE name = 'E2E Reveal Zone'")->execute();
$db->prepare(
    "INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, maxzoom, status)
     VALUES ('E2E Reveal Zone', 20.95, 52.20, 21.10, 52.28, 14, 'ready')"
)->execute();
$revealZoneId = (int)$db->lastInsertId();
foreach (glob(__DIR__ . '/../tiles/zone_*.pmtiles') ?: [] as $staleZone) {
    @unlink($staleZone);
}
copy(
    __DIR__ . '/fixtures/micro.pmtiles',
    __DIR__ . '/../tiles/zone_' . $revealZoneId . '.pmtiles'
);

echo "E2E fixtures seeded\n";
