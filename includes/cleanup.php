<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/order_state.php';
require_once dirname(__DIR__) . '/includes/proxy.php';
require_once dirname(__DIR__) . '/includes/settings.php';

// Core deletion logic — single source of truth used by both pseudo-cron and CLI cron.
// The actual work lives in order_state.php: per-order transactions with row
// locks, DB-authoritative deletes, file unlinking only after commit. It is
// idempotent and safe to run concurrently with receiving, revealing or
// another cleanup pass (see CleanupTest / StateTransitionTest).
function do_cleanup(): int {
    _purge_stale_rate_limits();
    // Truncation anchor for the audit log (best-effort, never throws):
    // covers both the real cron and the pseudo-cron path.
    log_checkpoint_write();
    return cleanup_expired_orders();
}

// rate_limits rows are one-per-IP×scope and only ever reset on window expiry
// or deleted on success — never swept. On a busy site (IPv6 rotation) the
// table bloats forever, so each cleanup pass drops windows older than twice
// the configured window. 2× margin: a row dropped a little early merely
// grants that IP a fresh budget, which fails open by at most one window.
function _purge_stale_rate_limits(): void {
    try {
        $cutoff = gmdate('Y-m-d H:i:s', time() - 2 * rl_window_seconds());
        get_db()->prepare('DELETE FROM rate_limits WHERE window_start < ?')
            ->execute([$cutoff]);
    } catch (Throwable $e) {
        log_err('Rate limit purge failed: ' . $e->getMessage());
    }
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
// Pure dice roll for the pseudo-cron gate: 1.0+ always runs, 0/negative
// never runs, anything in between runs with probability $chance. Kept pure
// so the probability decision is unit-testable without touching the
// process-level one-shot guard below. $rand exists for tests: random_int()
// throws on CSPRNG failure, and that failure arm must be covered without
// breaking the host's entropy source.
function _cleanup_roll(float $chance, ?callable $rand = null): bool {
    if ($chance >= 1.0) {
        return true;
    }
    if ($chance <= 0.0) {
        return false;
    }
    // A dead CSPRNG must not 500 every page (this runs on each visit):
    // fail toward cleanup — the pass itself is Throwable-guarded.
    $pick = $rand ?? static fn(int $min, int $max): int => random_int($min, $max);
    try {
        return $pick(1, max(1, (int)round(1 / $chance))) === 1;
    } catch (Throwable $e) {
        return true;
    }
}

// One expiry-sweep pass: stamp first (blocks concurrent duplicate runs),
// then sweep. The sweep is idempotent, so a crashed run merely delays the
// next one by an hour. Split out so the guarded wrapper stays trivial and
// the pass itself is directly testable (stale stamp, broken store).
function _run_cleanup_pass(): void {
    try {
        $last = (int)get_setting('last_cleanup', '0');
        if ((time() - $last) < 3600) return;

        // Stamp before work to block concurrent duplicate runs. A crashed run
        // merely delays the next one by an hour; nothing is lost because the
        // expiry sweep itself is idempotent.
        set_setting('last_cleanup', (string)time());
        do_cleanup();
        // Same hourly slot re-probes the stalest pool entries (bounded,
        // never throws): proxies nobody exercised must not keep a fresh
        // 'ok' forever. Real-cron installs get this via cron/cleanup.php.
        osm_proxy_revalidate_stale();
    } catch (Throwable $e) {
        log_err('Cleanup error: ' . $e->getMessage());
    }
}

function run_cleanup_if_due(float $chance = 0.01): void {
    static $ran = false;
    if ($ran) return;
    // A lost die roll does NOT consume the one-shot: skipping the DB check
    // on this visit must not silence the sweep for the rest of the process.
    // (Entropy failure is handled inside _cleanup_roll — fail toward cleanup.)
    if (!_cleanup_roll($chance)) return;
    $ran = true;
    _run_cleanup_pass();
}
