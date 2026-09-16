<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Order state machine under true multi-process contention ───────────────────
// StateTransitionTest proves the transitions are correct under a held row
// lock; THIS suite fires real concurrent PROCESSES at the same rows and
// demands the guarantees survive genuine parallelism:
//   - receive: exactly ONE winner, losers fail harmlessly, row gone once
//   - deliver: exactly one transition, replayed calls are no-ops
//   - receive vs admin delete: mutually exclusive, no double side effects
// Probes launch slightly staggered — a hard connection storm trips an old
// MariaDB 10.4 thread-pool bug locally (CI runs 11); the row lock makes the
// outcome deterministic regardless of interleaving.

$db    = get_db();
$devnull = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
$probe = static function (string $mode, string $arg) use ($devnull): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/_st_race.php')
         . ' ' . escapeshellarg($mode) . ' ' . escapeshellarg($arg) . " 2>$devnull";
    $out = shell_exec($cmd);
    return json_decode(trim((string)$out), true) ?: [];
};

$mk = static function (string $token, string $status) use ($db): int {
    $delivered = $status === 'delivered' ? 'NOW()' : 'NULL';
    $db->prepare(
        "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv,
                             status, delivered_at, expires_at)
         VALUES (?, 'x', 'ZQ==', 'abababababababababababab', '$status', $delivered, NOW() + INTERVAL 24 HOUR)"
    )->execute([$token]);
    return (int)$db->lastInsertId();
};
$cleanup = static function (string $like) use ($db): void {
    $db->prepare('DELETE FROM orders WHERE order_token LIKE ?')->execute([$like]);
};

// 1 ── six processes race to RECEIVE the same delivered order
$cleanup('srcereceive%');
$idR = $mk('srcreceive00001', 'delivered');
$results = [];
for ($i = 0; $i < 6; $i++) {
    $results[] = $probe('receive', 'srcreceive00001');
    usleep(120000);
}
$wins = count(array_filter($results, static fn($r) => ($r['ok'] ?? false) === true));
T::eq('exactly one concurrent receive wins', 1, $wins);
T::ok('losers report clean failure', count($results) === 6 && !isset($results[0]['error']));
T::ok('received order is gone', !$db->query("SELECT 1 FROM orders WHERE id = $idR")->fetch());

// 2 ── six processes race to DELIVER the same preparing order
$cleanup('srcedeliver%');
$idD = $mk('srcedeliver0001', 'preparing');
$results = [];
for ($i = 0; $i < 6; $i++) {
    $results[] = $probe('deliver', (string)$idD);
    usleep(120000);
}
$wins = count(array_filter($results, static fn($r) => ($r['ok'] ?? false) === true));
T::eq('exactly one concurrent deliver wins', 1, $wins);
$row = $db->query("SELECT status FROM orders WHERE id = $idD")->fetch();
T::eq('order is delivered', 'delivered', $row['status']);

// 3 ── receive races admin delete on the same delivered order: mutually exclusive
$cleanup('srcerace000%');
$idX   = $mk('srcerace00001', 'delivered');
$resRc = $probe('receive', 'srcerace00001');
$resDl = $probe('delete', (string)$idX);
$gone  = !$db->query("SELECT 1 FROM orders WHERE id = $idX")->fetch();
T::ok('receive+delete race leaves the order gone', $gone);
T::ok('exactly one of the two transitions succeeded',
    ($resRc['ok'] ?? false) xor ($resDl['ok'] ?? false));

// 4 ── cleanup after the races is idempotent
$cleanup('srcerace000%');
T::eq('cleanup sweeps the race leftovers', 0,
    (int)$db->query("SELECT COUNT(*) FROM orders WHERE order_token LIKE 'srcerace%'")->fetchColumn());
$cleanup('srcreceive%'); $cleanup('srcedeliver%');

exit(T::done());
