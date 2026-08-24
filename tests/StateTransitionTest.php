<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Atomic order state machine ────────────────────────────────────────────────
// preparing → delivered → received/deleted. Every test here tries to break
// the transitions: replays, out-of-order calls, expiry races and genuine
// row-lock contention (a second raw PDO connection holds the lock while the
// function under fight runs against get_db()).

$db = get_db();
$db->exec("DELETE FROM orders WHERE order_token LIKE 'stt%'");

$mk = static function (string $token, string $status, ?string $expires = null) use ($db): int {
    $delivered = $status === 'delivered' ? 'NOW()' : 'NULL';
    $exp       = $expires ?? 'NULL';
    $db->prepare(
        "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv,
                             status, delivered_at, expires_at)
         VALUES (?, 'x', 'ZQ==', 'abababababababababababab', '$status', $delivered, $exp)"
    )->execute([$token]);
    return (int)$db->lastInsertId();
};

// A second connection for deterministic contention.
$lockDsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', DB_HOST, DB_PORT, DB_NAME);
$lockConn = new PDO($lockDsn, DB_USER, DB_PASS, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);
$lockConn->exec('SET SESSION innodb_lock_wait_timeout = 1');
get_db()->exec('SET SESSION innodb_lock_wait_timeout = 1');

// 1 ── deliver: exactly once
$idP = $mk('sttdeliver000001', 'preparing');
T::ok('deliver succeeds from preparing', order_deliver_atomic($idP, 24));
$row = $db->query('SELECT status, delivered_at, expires_at FROM orders WHERE id = ' . $idP)->fetch();
T::eq('deliver sets status', 'delivered', $row['status']);
T::ok('deliver stamps delivered_at', $row['delivered_at'] !== null);
T::ok('deliver sets expiry ~TTL', abs(strtotime($row['expires_at']) - time() - 24 * 3600) < 60);
T::ok('replayed delivery is a harmless no-op', !order_deliver_atomic($idP, 24));
T::ok('nonexistent id delivers nothing', !order_deliver_atomic(99999999, 24));

// 2 ── receive BEFORE delivery must not delete anything
$idPrep = $mk('sttreceive0002', 'preparing');
T::ok('receive refuses a preparing order', !order_receive_atomic('sttreceive0002'));
T::ok('refused receive leaves the order intact',
    (bool)$db->query('SELECT 1 FROM orders WHERE id = ' . $idPrep)->fetch());

// 3 ── receive AFTER delivery: exactly once
$idDel = $mk('sttreceive0003', 'delivered');
T::ok('receive accepts a delivered order', order_receive_atomic('sttreceive0003'));
T::ok('received order is gone', !$db->query('SELECT 1 FROM orders WHERE id = ' . $idDel)->fetch());
T::ok('repeated receive fails harmlessly', !order_receive_atomic('sttreceive0003'));
T::ok('unknown token receives nothing', !order_receive_atomic('sttnope00000000'));

// 4 ── an expired-but-not-yet-cleaned order can still be received once
$idExp = $mk('sttreceive0004', 'delivered', 'NOW() - INTERVAL 1 HOUR');
T::ok('expired order still receivable (expiry is cleanup, not a state)', order_receive_atomic('sttreceive0004'));

// 5 ── concurrent receive: row locked elsewhere → clean failure, then success
$idC = $mk('sttracing00005', 'delivered');
$lockConn->beginTransaction();
$lockConn->prepare('SELECT id FROM orders WHERE id = ? FOR UPDATE')->execute([$idC]);
T::ok('locked row makes receive fail safely', !order_receive_atomic('sttracing00005'));
T::ok('failed concurrent receive did NOT delete', (bool)$db->query('SELECT 1 FROM orders WHERE id = ' . $idC)->fetch());
$lockConn->rollBack();
T::ok('after lock release receive succeeds once', order_receive_atomic('sttracing00005'));

// 6 ── cleanup racing receive / reveal: locked expired row is skipped, next pass gets it
$idX = $mk('sttcleanup006', 'delivered', 'NOW() - INTERVAL 2 HOUR');
$lockConn->beginTransaction();
$lockConn->prepare('SELECT id FROM orders WHERE id = ? FOR UPDATE')->execute([$idX]);
T::eq('cleanup skips a locked expired order', 0, do_cleanup());
T::ok('skipped order survives', (bool)$db->query('SELECT 1 FROM orders WHERE id = ' . $idX)->fetch());
$lockConn->rollBack();
T::eq('cleanup deletes it on the retry pass', 1, do_cleanup());

// 7 ── admin delete: token returned exactly once
$idA = $mk('sttdelete00007', 'delivered');
$res = order_delete_atomic($idA);
T::ok('delete returns token on success', is_array($res) && $res['token'] === 'sttdelete00007');
T::ok('deleted twice returns nothing', order_delete_atomic($idA) === null);

// 8 ── the DB CHECK constraint is the last line of defense:
// a delivered row without delivered_at cannot exist through any code path.
$schemaHasCheck = (bool)$db->query(
    "SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
     WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'orders'
       AND CONSTRAINT_NAME = 'chk_orders_state'"
)->fetchColumn();
T::ok('state-machine CHECK constraint present', $schemaHasCheck);
if ($schemaHasCheck) {
    $threw = false;
    try {
        $db->exec("INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status)
                   VALUES ('sttcheck00008', 'x', 'e', 'abab', 'delivered')");
    } catch (Throwable) {
        $threw = true;
    }
    T::ok('impossible state rejected by the database', $threw);
}

// 9 ── migration from a representative pre-migration state: drop the guard,
// plant an anomalous row, re-run setup.sql, expect normalization + constraint back.
$db->exec('ALTER TABLE orders DROP CONSTRAINT chk_orders_state');
$db->exec("INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status, expires_at)
           VALUES ('sttmigrate09', 'x', 'e', 'abab', 'delivered', NOW() + INTERVAL 24 HOUR)");
$anomalyId = (int)$db->lastInsertId();

$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/schema_loader.php') . ' 2>&1';
exec($cmd, $out, $code);
T::eq('schema re-run (migration) exits 0', 0, $code);

$mig = $db->query('SELECT delivered_at, expires_at FROM orders WHERE id = ' . $anomalyId)->fetch();
T::ok('anomalous delivered row normalized by migration', $mig !== false && $mig['delivered_at'] !== null);
T::ok('normalized row kept its expiry', $mig !== false && $mig['expires_at'] !== null);
T::ok('CHECK constraint restored after migration', (bool)$db->query(
    "SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
     WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'orders'
       AND CONSTRAINT_NAME = 'chk_orders_state'"
)->fetchColumn());

// Cleanup
$db->exec("DELETE FROM orders WHERE order_token LIKE 'stt%'");
unset($lockConn);

exit(T::done());
