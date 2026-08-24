<?php
declare(strict_types=1);

// Probe used by RateLimitTest: breaks the rate-limit subsystem (renames the
// table) and reports what rl_status() decides. The limiter must FAIL CLOSED.
// Always restores the table before exiting.

require_once __DIR__ . '/bootstrap.php';

$db = get_db();
$restored = false;
try {
    $db->exec('RENAME TABLE rate_limits TO rate_limits_probe_bak');
    try {
        $s = rl_status('public');
        echo json_encode([
            'blocked'   => $s['blocked'],
            'remaining' => $s['remaining'],
        ]);
    } catch (Throwable $e) {
        // An exception escaping to the caller is ALSO fail-closed behavior
        // (the request dies) — but rl_status should catch internally.
        echo json_encode(['blocked' => true, 'remaining' => -1, 'threw' => true]);
    }
} finally {
    $db->exec('RENAME TABLE rate_limits_probe_bak TO rate_limits');
    $restored = true;
}
exit($restored ? 0 : 1);
