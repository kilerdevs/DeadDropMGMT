<?php
/**
 * Dead Drop cleanup — CLI cron script.
 * On hosts without cron (e.g. byethost free), cleanup runs automatically
 * via pseudo-cron triggered by page visits (see includes/cleanup.php).
 *
 * Cron example:  0 * * * * php /path/to/cron/cleanup.php
 */
declare(strict_types=1);

define('BASE_DIR', dirname(__DIR__));
require_once BASE_DIR . '/config.php';
require_once BASE_DIR . '/includes/db.php';
require_once BASE_DIR . '/includes/settings.php';
require_once BASE_DIR . '/includes/cleanup.php';

try {
    $deleted = do_cleanup();

    // Sync the pseudo-cron timestamp so the next page visit doesn't double-run
    set_setting('last_cleanup', (string)time());

    echo '[' . date('Y-m-d H:i:s') . "] Done — {$deleted} order(s) deleted.\n";
} catch (Throwable $e) {
    log_err('Cron cleanup error: ' . $e->getMessage());
    echo '[' . date('Y-m-d H:i:s') . '] ERROR: ' . $e->getMessage() . "\n";
    exit(1);
}
