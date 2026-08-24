<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/order_state.php';

// Core deletion logic — single source of truth used by both pseudo-cron and CLI cron.
// The actual work lives in order_state.php: per-order transactions with row
// locks, DB-authoritative deletes, file unlinking only after commit. It is
// idempotent and safe to run concurrently with receiving, revealing or
// another cleanup pass (see CleanupTest / StateTransitionTest).
function do_cleanup(): int {
    return cleanup_expired_orders();
}

// Pseudo-cron wrapper — throttled to at most once per hour, called on each page visit.
function run_cleanup_if_due(): void {
    static $ran = false;
    if ($ran) return;
    $ran = true;

    try {
        $last = (int)get_setting('last_cleanup', '0');
        if ((time() - $last) < 3600) return;

        // Stamp before work to block concurrent duplicate runs. A crashed run
        // merely delays the next one by an hour; nothing is lost because the
        // expiry sweep itself is idempotent.
        set_setting('last_cleanup', (string)time());
        do_cleanup();
    } catch (Throwable $e) {
        log_err('Cleanup error: ' . $e->getMessage());
    }
}
