<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Panic wipe: destroys everything, reports honestly, retries safely ────────

$db = get_db();
$up = dirname(__DIR__) . '/uploads';
if (!is_dir($up)) { mkdir($up, 0770, true); }

// Baseline reset — tolerant of leftovers from an interrupted earlier run
$db->exec('SET FOREIGN_KEY_CHECKS = 0');
foreach (['orders', 'order_photos', 'order_events', 'audit_log', 'rate_limits'] as $t) {
    $db->exec("DELETE FROM $t");
}
$db->exec('SET FOREIGN_KEY_CHECKS = 1');
foreach (glob($up . '/*', GLOB_ONLYDIR) ?: [] as $d) { @chmod($d, 0770); }
foreach (glob($up . '/*/*') ?: [] as $f) { @unlink($f); }
foreach (glob($up . '/*', GLOB_ONLYDIR) ?: [] as $d) { @rmdir($d); }

$mkOrder = static function (string $token, string $status) use ($db): int {
    $delivered = $status === 'delivered' ? 'NOW()' : 'NULL';
    $db->prepare(
        "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv,
                             status, delivered_at, expires_at)
         VALUES (?, 'x', 'ZQ==', 'abababababababababababab', '$status', $delivered, NOW() + INTERVAL 24 HOUR)"
    )->execute([$token]);
    return (int)$db->lastInsertId();
};

$id1 = $mkOrder('panicorder01', 'delivered');
$id2 = $mkOrder('panicorder02', 'preparing');

$hex1 = bin2hex(random_bytes(14));
$hex2 = bin2hex(random_bytes(14));
mkdir("$up/$id1", 0770, true);
mkdir("$up/$id2", 0770, true);
file_put_contents("$up/$id1/$hex1.jpg", str_repeat('A', 4096));
file_put_contents("$up/$id2/$hex2.png", str_repeat('B', 2048));
$db->prepare('INSERT INTO order_photos (order_id, filename) VALUES (?, ?)')
   ->execute([$id1, "$id1/$hex1.jpg"]);
$db->prepare('INSERT INTO order_photos (order_id, filename) VALUES (?, ?)')
   ->execute([$id2, "$id2/$hex2.png"]);
$db->exec("INSERT INTO order_events (event_type, ip_address) VALUES ('unlock_success', '203.0.113.5')");
$db->exec("INSERT INTO audit_log (username, action, ip_address) VALUES ('owner', 'order_create', '203.0.113.5')");
$db->exec("INSERT INTO rate_limits (ip_address, scope, count, window_start)
           VALUES ('203.0.113.5', 'public', 3, UTC_TIMESTAMP())");

$report = do_panic_wipe();

T::eq('report counts every order', 2, $report['orders']);
T::eq('report counts every photo row', 2, $report['photos']);
T::ok('report counts events', ($report['events'] ?? -1) >= 1);
T::ok('report counts audit entries', ($report['audit'] ?? -1) >= 1);

T::eq('orders table emptied', 0, (int)$db->query('SELECT COUNT(*) FROM orders')->fetchColumn());
T::eq('photo rows cascaded away', 0, (int)$db->query('SELECT COUNT(*) FROM order_photos')->fetchColumn());
T::eq('event log destroyed', 0, (int)$db->query('SELECT COUNT(*) FROM order_events')->fetchColumn());
T::eq('audit log destroyed too (ADR-015)', 0, (int)$db->query('SELECT COUNT(*) FROM audit_log')->fetchColumn());
T::eq('rate-limit rows destroyed', 0, (int)$db->query('SELECT COUNT(*) FROM rate_limits')->fetchColumn());

T::ok('photo file #1 shredded from disk', !is_file("$up/$id1/$hex1.jpg"));
T::ok('photo file #2 shredded from disk', !is_file("$up/$id2/$hex2.png"));
T::ok('upload directories removed', !is_dir("$up/$id1") && !is_dir("$up/$id2"));
T::ok('no filesystem failures reported on clean run', ($report['files_failed'] ?? 99) === 0);
T::eq('files deleted reported accurately', 2, $report['files']);

// Accounts and settings deliberately survive — the install stays usable.
$settingsRows = (int)$db->query('SELECT COUNT(*) FROM settings')->fetchColumn();
T::ok('settings survive the wipe', $settingsRows > 0);

// Retry after a complete run: zeros across the board, no errors.
$retry = do_panic_wipe();
T::eq('re-run finds no orders', 0, $retry['orders']);
T::eq('re-run deletes no files', 0, $retry['files']);
T::eq('re-run has no failures', 0, $retry['files_failed']);

// Partial failure must be OBSERVABLE: an undeletable file is reported, not
// hidden behind a success message; and the retry finishes the job.
mkdir("$up/999001", 0770, true);
file_put_contents("$up/999001/stubborn.jpg", str_repeat('C', 512));
// Cross-platform "undeletable": POSIX honours the directory mode, Windows
// only the read-only attribute on the file itself.
chmod("$up/999001", 0550);
chmod("$up/999001/stubborn.jpg", 0444);
$partial = do_panic_wipe(); // DB is already empty; sweep still walks the tree
T::ok('undeletable file reported as failed', ($partial['files_failed'] ?? 0) >= 1);
chmod("$up/999001/stubborn.jpg", 0644); // make it deletable again
chmod("$up/999001", 0770);
$final = do_panic_wipe();
T::ok('stubborn file cleaned once writable again',
    !is_file("$up/999001/stubborn.jpg") && ($final['files_failed'] ?? 99) === 0);
@rmdir("$up/999001");

exit(T::done());
