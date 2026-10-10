<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Probe used by RateLimitTest: hides BOTH rate_limits and users (pre-schema
// bootstrap — the very first owner creation) and reports what rl_status()
// decides. The limiter must FAIL OPEN here: failing closed bricks fresh
// installs. Always restores both tables before exiting.

require_once __DIR__ . '/bootstrap.php';

$db = get_db();
try {
    $db->exec('SET FOREIGN_KEY_CHECKS=0');
    $db->exec('RENAME TABLE rate_limits TO rate_limits_probe_bak');
    $db->exec('RENAME TABLE users TO users_probe_bak');
    try {
        $s = rl_status('public');
        echo json_encode([
            'blocked'   => $s['blocked'],
            'remaining' => $s['remaining'],
            'count'     => $s['count'],
        ]);
    } catch (Throwable $e) {
        // An exception here fails the bootstrap open too (the request dies
        // before any owner exists) — report it as blocked.
        echo json_encode(['blocked' => true, 'remaining' => -1, 'threw' => true]);
    }
} finally {
    try {
        $db->exec('RENAME TABLE users_probe_bak TO users');
    } catch (Throwable) {
    }
    try {
        $db->exec('RENAME TABLE rate_limits_probe_bak TO rate_limits');
    } catch (Throwable) {
    }
    try {
        $db->exec('SET FOREIGN_KEY_CHECKS=1');
    } catch (Throwable) {
    }
}
exit(0);
