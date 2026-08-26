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
//
// $chance gates the DB lookup itself: on a busy site the once-per-hour check
// still meant one extra settings read per request. Each request now rolls a
// 1-in-100 die BEFORE touching the database; combined with the hourly
// throttle the sweep still runs promptly (a site with any real traffic rolls
// the die hundreds of times an hour), while a quiet site pays at most one
// cheap read per request it already makes. Pass 1.0 to force evaluation in
// tests. High-volume deployments should install real cron anyway —
// cron/cleanup.php calls do_cleanup() directly and bypasses all gating.
function run_cleanup_if_due(float $chance = 0.01): void {
    static $ran = false;
    if ($ran) return;
    $ran = true;

    if ($chance < 1.0) {
        // 0/negative means "never roll the dice" (used by tests); anything
        // below 1.0 rolls once and usually goes back to sleep.
        if ($chance <= 0.0 || random_int(1, max(1, (int)round(1 / $chance))) !== 1) {
            return;
        }
    }

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
