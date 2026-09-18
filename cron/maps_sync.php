<?php
/**
 * Dead Drop map-zone sync - CLI worker (and detached background job).
 *
 * Advances queued map zones one at a time: CLI ensure → planet build →
 * dry-run sizing → disk check → extract with live progress → verify →
 * atomic publish. Long-running by design (minutes to hours through pool
 * proxies); run it from system cron and/or let the admin UI kick it
 * detached after queueing:
 *
 * Cron example (every 15 minutes):
 *     php /path/to/cron/maps_sync.php
 *
 * Never invoked from a page visit: extracts cannot resume, so a killed web
 * request would waste the whole transfer. Stalled jobs are failed by the
 * hourly maps_steward() instead (see includes/maps.php).
 */
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

define('BASE_DIR', dirname(__DIR__));
require_once BASE_DIR . '/includes/kernel.php';

@set_time_limit(0);

[$locked, $holder] = maps_worker_lock();
if (!$locked) {
    echo '[' . date('Y-m-d H:i:s') . "] Another worker holds the lock: {$holder}\n";
    exit(0);
}

$done = 0;
$failed = 0;
try {
    while (true) {
        $next = null;
        try {
            $rows = get_db()->query(
                "SELECT * FROM map_zones WHERE status = 'queued' ORDER BY id ASC LIMIT 1"
            )->fetchAll();
            $next = $rows[0] ?? null;
        } catch (Throwable $e) {
            log_err('Maps worker queue read: ' . $e->getMessage());
            break;
        }
        if ($next === null) {
            break;
        }
        maps_worker_touch();
        [$ok, $err] = maps_process_one($next);
        if ($ok) {
            $done++;
            echo '[' . date('Y-m-d H:i:s') . '] Zone ' . $next['id'] . " ready\n";
        } else {
            $failed++;
            echo '[' . date('Y-m-d H:i:s') . '] Zone ' . $next['id'] . " failed: {$err}\n";
        }
    }
    echo '[' . date('Y-m-d H:i:s') . "] Done - {$done} ready, {$failed} failed.\n";
} finally {
    maps_worker_unlock();
}
