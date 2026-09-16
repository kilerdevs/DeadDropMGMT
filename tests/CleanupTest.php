<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Expiry cleanup: deletes expired orders, photos and files; keeps the rest ─

$db  = get_db();
$up  = dirname(__DIR__) . '/uploads';
if (!is_dir($up)) { mkdir($up, 0770, true); }

// Seed: expired order (with photo file), active order, never-expiring order.
// Delivered rows carry delivered_at — the schema's state-machine CHECK
// requires it, exactly like production code sets it.
$mk = static function (string $token, ?string $expires) use ($db): int {
    $db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$token]);
    $db->prepare('INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status, delivered_at, expires_at)
                  VALUES (?, "x", "e", "abab", "delivered", NOW(), ' . ($expires ?? 'NULL') . ')')
       ->execute([$token]);
    return (int)$db->lastInsertId();
};
$expiredId = $mk('clstoken00000001', 'NOW() - INTERVAL 2 HOUR');
$activeId  = $mk('clstoken00000002', 'NOW() + INTERVAL 2 HOUR');
$noExpiry  = $mk('clstoken00000003', null);

$hex = bin2hex(random_bytes(14));
$dir = "$up/$expiredId/";
if (!is_dir($dir)) { mkdir($dir, 0770, true); }
file_put_contents("$dir$hex.jpg", str_repeat('JPEGDUMMY', 100));
$db->prepare('INSERT INTO order_photos (order_id, filename) VALUES (?, ?)')
   ->execute([$expiredId, "$expiredId/$hex.jpg"]);

// A photo row whose filename does NOT match the safe pattern must not cause
// an unlink outside uploads/<id>/<hex>.<ext> — it is simply skipped.
$db->prepare('INSERT INTO order_photos (order_id, filename) VALUES (?, ?)')
   ->execute([$expiredId, '../../config.php']);

$deleted = do_cleanup();

T::eq('exactly one order deleted', 1, $deleted);
T::ok('expired order gone', !$db->query('SELECT 1 FROM orders WHERE id = ' . $expiredId)->fetch());
T::ok('active order kept', (bool)$db->query('SELECT 1 FROM orders WHERE id = ' . $activeId)->fetch());
T::ok('never-expiring order kept', (bool)$db->query('SELECT 1 FROM orders WHERE id = ' . $noExpiry)->fetch());
T::ok('photo file unlinked from disk', !is_file("$dir$hex.jpg"));
T::ok('order directory removed', !is_dir($dir));

// overwrite_and_unlink zeroes content before unlinking (best-effort overwrite)
$tmp = tempnam(sys_get_temp_dir(), 'ddl');
file_put_contents($tmp, 'topsecret');
overwrite_and_unlink($tmp);
T::ok('overwrite_and_unlink removes the file', !is_file($tmp));
T::ok('overwrite_and_unlink tolerates missing path', true);
overwrite_and_unlink($tmp . '-does-not-exist');

// ── Pseudo-cron plumbing: dice and pass are directly testable halves ──────
T::ok('dice always runs at 1.0', _cleanup_roll(1.0) === true);
T::ok('dice never runs at 0.0', _cleanup_roll(0.0) === false);
T::ok('dice never runs when negative', _cleanup_roll(-0.5) === false);
T::ok('dice answers boolean in between', is_bool(_cleanup_roll(0.01)));

$stampOf = static function () use ($db): int {
    return (int)$db->query("SELECT value FROM settings WHERE key_name = 'last_cleanup'")->fetchColumn();
};
// A skipped roll touches nothing and does NOT consume the process one-shot
// (deliberately chance 0.0 here — CleanupTest must not arm the wrapper's
// guard or SettingsTest's sweep assertion in the shared coverage process
// would starve).
set_setting('last_cleanup', (string)(time() - 7200));
$before = $stampOf();
run_cleanup_if_due(0.0);
T::eq('skipped roll leaves a stale stamp alone', $before, $stampOf());

// A broken store cannot turn a pass into a crash (cold settings cache +
// hidden table forces the real DB read to throw into the catch).
$cache = &_settings_store();
$cache = null;
$db->exec('RENAME TABLE settings TO settings_cl_bak');
try {
    _run_cleanup_pass();
    T::ok('broken store cannot crash a pass', true);
} finally {
    $db->exec('RENAME TABLE settings_cl_bak TO settings');
}

// The pass itself sweeps when due...
set_setting('last_cleanup', (string)(time() - 7200));
_run_cleanup_pass();
$after = $stampOf();
T::ok('direct pass stamps and sweeps when due', $after > $before);
// ...and stays quiet when the throttle holds.
_run_cleanup_pass();
T::eq('direct pass respects the hourly throttle', $after, $stampOf());

// Cleanup
$db->prepare('DELETE FROM orders WHERE order_token LIKE "clstoken%"')->execute();

exit(T::done());
