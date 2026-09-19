<?php
/**
 * Dead Drop cleanup — CLI cron script.
 * On hosts without cron (e.g. byethost free), cleanup runs automatically
 * via pseudo-cron triggered by page visits (see includes/cleanup.php).
 *
 * Cron example:  0 * * * * php /path/to/cron/cleanup.php
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

try {
    $deleted = do_cleanup();
    // Same maintenance slot as the pseudo-cron: re-probe the stalest pool
    // entries (bounded, never throws). Available via includes/cleanup.php.
    osm_proxy_revalidate_stale();

    // Sync the pseudo-cron timestamp so the next page visit doesn't double-run
    set_setting('last_cleanup', (string)time());

    echo '[' . date('Y-m-d H:i:s') . "] Done — {$deleted} order(s) deleted.\n";

    // Last, because discovery is slow: swap confirmed-dead discovered proxies
    // for fresh ones (no-op unless routing is on and one is marked failed).
    $heal = osm_proxy_heal(null, null, true);
    if ($heal['skipped'] === null) {
        echo '[' . date('Y-m-d H:i:s') . "] Proxy pool: replaced {$heal['replaced']} of {$heal['dead']} dead.\n";
    }
} catch (Throwable $e) {
    log_err('Cron cleanup error: ' . $e->getMessage());
    echo '[' . date('Y-m-d H:i:s') . '] ERROR: ' . $e->getMessage() . "\n";
    exit(1);
}
