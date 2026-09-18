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
    _purge_stale_records();
    _warn_legacy_tokens();
    osm_tile_cache_prune();
    return cleanup_expired_orders();
}

// Retention for tables nothing else ever trims. Events for tokens that never
// matched an order (typos, probes) have no order whose deletion would take
// them along; the audit trail keeps a year, long enough for any review.
const ORPHAN_EVENT_RETENTION_DAYS = 30;
const AUDIT_RETENTION_DAYS = 365;

function _purge_stale_records(): void {
    try {
        $db = get_db();
        $db->prepare(
            'DELETE e FROM order_events e
             LEFT JOIN orders o ON o.id = e.order_id OR o.token_hmac = e.token_hmac
             WHERE o.id IS NULL AND e.created_at < (NOW() - INTERVAL ' . ORPHAN_EVENT_RETENTION_DAYS . ' DAY)'
        )->execute();
        $db->prepare(
            'DELETE FROM audit_log WHERE created_at < (NOW() - INTERVAL ' . AUDIT_RETENTION_DAYS . ' DAY)'
        )->execute();
    } catch (Throwable $e) {
        log_err('Record purge failed: ' . $e->getMessage());
    }
}

// Orders that predate hashed tokens (ADR-019) cannot be found by the app until
// tools/migrate_order_tokens.php has moved them over. Say so once per sweep —
// a recipient's "not found" would otherwise be the only symptom.
function _warn_legacy_tokens(): void {
    try {
        $db = get_db();
        $has = (int)$db->query(
            "SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'order_token'"
        )->fetchColumn();
        if ($has === 0) {
            return;
        }
        $n = (int)$db->query('SELECT COUNT(*) FROM orders WHERE order_token IS NOT NULL AND token_hmac IS NULL')->fetchColumn();
        if ($n > 0) {
            log_warn('legacy_order_tokens', ['msg' => $n . ' order(s) still carry a plaintext token and cannot be looked up — run: php tools/migrate_order_tokens.php']);
        }
    } catch (Throwable $e) {
        log_err('Legacy token check failed: ' . $e->getMessage());
    }
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
// $chance gates the DB lookup itself. The default is 1.0 (always evaluate):
// the settings table is loaded once per request anyway (get_settings() reads
// every row in one query), so checking the hourly stamp costs nothing — while
// a 1-in-100 die made the sweep effectively daily on a quiet dead drop, i.e.
// expired orders lingered for days. Lower it only where the stamp read is
// measurably hot. High-volume deployments should still install real cron —
// cron/cleanup.php calls do_cleanup() directly and bypasses all gating (the
// Docker entrypoint runs it on a timer).
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

function run_cleanup_if_due(float $chance = 1.0): void {
    static $ran = false;
    if ($ran) return;
    // A lost die roll does NOT consume the one-shot: skipping the DB check
    // on this visit must not silence the sweep for the rest of the process.
    // (Entropy failure is handled inside _cleanup_roll — fail toward cleanup.)
    if (!_cleanup_roll($chance)) return;
    $ran = true;
    _run_cleanup_pass();
}
