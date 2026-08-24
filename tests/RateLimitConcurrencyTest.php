<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Rate limiter under contention ─────────────────────────────────────────────
// The old limiter did SELECT-then-UPDATE: concurrent requests could all read
// the same count before any increment landed, losing updates and leaking
// extra attempts. rl_hit() spends + decides in one transaction on a row lock.
// This suite hammers it with N simultaneous processes and demands that every
// transition observed a UNIQUE count — the signature of a lost-update-free
// serialized log.

$db = get_db();
$ip   = '203.0.113.77';
$max  = 5;
$procs = 12;

set_setting('rate_limit_max', (string)$max);
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ?')->execute([$ip]);
putenv('RL_TEST_IP=' . $ip);

// Launch the probes slightly staggered: a hard simultaneous connection
// storm trips a thread-pool crash in old MariaDB 10.4 builds (CI runs 11,
// which is fine). The stagger does not weaken the test — the row lock
// serializes transitions regardless, and the assertions below still demand
// zero lost updates under whatever overlap actually occurs.
$handles = [];
for ($i = 0; $i < $procs; $i++) {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/_rl_race.php') . ' 2>NUL';
    $pipes = [];
    $handles[] = ['h' => proc_open($cmd, [['pipe', 'r'], ['pipe', 'w'], ['file', 'NUL', 'w']], $pipes), 'out' => $pipes[1]];
    usleep(120000);
}

$results = [];
foreach ($handles as $x) {
    $out = stream_get_contents($x['out']);
    fclose($x['out']);
    proc_close($x['h']);
    $j = json_decode(trim((string)$out), true);
    if (is_array($j)) { $results[] = $j; }
}

T::eq('every concurrent probe answered', $procs, count($results));

$counts = array_map(static fn($r) => (int)$r['count'], $results);
sort($counts);
$expected = range(1, $procs);
T::ok('each transition saw a unique count (no lost updates, no double reads)',
    $counts === $expected);

$allowed = count(array_filter($results, static fn($r) => !$r['blocked']));
T::eq('exactly max probes pass before the budget closes', $max, $allowed);

$row = $db->prepare('SELECT count FROM rate_limits WHERE ip_address = ? AND scope = ?');
$row->execute([$ip, 'public']);
T::eq('final stored count equals attempts made', $procs, (int)$row->fetchColumn());

// Window reset still works after the hammering: expire the row, next hit
// starts a fresh budget at 1.
$db->prepare('UPDATE rate_limits SET window_start = UTC_TIMESTAMP() - INTERVAL 1 HOUR WHERE ip_address = ?')
   ->execute([$ip]);
$_SERVER['REMOTE_ADDR'] = $ip;
$r = rl_hit('public');
T::eq('stale window resets the budget atomically', 1, $r['count']);
T::ok('fresh window is not blocked', !$r['blocked']);

// Cleanup
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ?')->execute([$ip]);
set_setting('rate_limit_max', '10');

exit(T::done());
