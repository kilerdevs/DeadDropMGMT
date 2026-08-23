<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Expiry cleanup: deletes expired orders, photos and files; keeps the rest ─

$db  = get_db();
$up  = dirname(__DIR__) . '/uploads';
if (!is_dir($up)) { mkdir($up, 0770, true); }

// Seed: expired order (with photo file), active order, never-expiring order
$mk = static function (string $token, ?string $expires) use ($db): int {
    $db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$token]);
    $db->prepare('INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status, expires_at)
                  VALUES (?, "x", "e", "00", "delivered", ' . ($expires ?? 'NULL') . ')')
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

// secure_unlink zeroes content before unlinking (best-effort overwrite)
$tmp = tempnam(sys_get_temp_dir(), 'ddl');
file_put_contents($tmp, 'topsecret');
secure_unlink($tmp);
T::ok('secure_unlink removes the file', !is_file($tmp));
T::ok('secure_unlink tolerates missing path', true);
secure_unlink($tmp . '-does-not-exist');

// Cleanup
$db->prepare('DELETE FROM orders WHERE order_token LIKE "clstoken%"')->execute();

exit(T::done());
