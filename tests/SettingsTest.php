<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

// ── Settings store semantics, clamping helpers, pseudo-cron throttle ─────────

$db = get_db();

// Cache coherence: a write is visible immediately even after the cache was built
set_setting('t_cov_key', 'alpha');
T::eq('write-through read-back', 'alpha', get_setting('t_cov_key'));
set_setting('t_cov_key', 'beta');
T::eq('second write overwrites', 'beta', get_setting('t_cov_key'));

// Missing key yields the caller's default
T::eq('missing key returns default', 'fallback-x', get_setting('no_such_key_zzz', 'fallback-x'));
T::eq('missing key without default is empty', '', get_setting('no_such_key_zzz'));

// Unreadable store fails soft: empty cache + error log, never an exception
with_table_hidden_st('settings', function (): void {
    // force a reload from the (missing) table
    $cache = &_settings_store();
    $cache = null;
    T::eq('unreadable settings yield empty cache', [], get_settings());
    T::ok('site_name falls back without settings table', site_name() !== '');
});
// Restore a clean cache now that the table is back
$cache = &_settings_store();
$cache = null;

// Clamping helpers — hostile values must not produce hostile behaviour
set_setting('order_ttl_hours', '-5');
T::eq('ttl clamps to at least 1h', 1, order_ttl_hours());
set_setting('rate_limit_max', '0');
T::eq('rl max clamps to at least 1', 1, rl_max());
set_setting('rate_limit_window_min', '0');
T::eq('window clamps to at least 60s', 60, rl_window_seconds());
set_setting('admin_session_hours', '0.01');
T::eq('admin session clamps to at least 1800s', 1800, admin_session_seconds());
set_setting('max_photo_mb', '-3');
T::eq('photo budget clamps positive', true, max_photo_bytes() > 0);

// Boolean-ish getters
set_setting('compliance_note_enabled', '1');
T::ok('compliance note on', compliance_note_enabled());
set_setting('compliance_note_enabled', '0');
T::ok('compliance note off', !compliance_note_enabled());
set_setting('osm_proxy_enabled', '1');
T::ok('osm proxy routing on', osm_proxy_enabled());
set_setting('osm_proxy_enabled', '0');
T::ok('osm proxy routing off', !osm_proxy_enabled());

// extend_hours_options parsing: spaces tolerated, junk dropped, sane default
set_setting('extend_hours_options', ' 12 , x, -4, 36 ');
T::eq('options parse and clean', [12, 36], extend_hours_options());
set_setting('extend_hours_options', ',,,');
T::eq('garbage options fall back to default', [24, 48, 72], extend_hours_options());

// Countdown formatting
T::eq('zero formats as expired', t('common.expired'), format_countdown(0));
T::eq('negative formats as expired', t('common.expired'), format_countdown(-5));
T::ok('hours render', str_contains(format_countdown(7265), '2h'));
T::ok('minutes-only render', str_contains(format_countdown(125), '2m'));
T::ok('seconds-only render', str_contains(format_countdown(42), '42s'));

// ── Pseudo-cron ───────────────────────────────────────────────────────────────
// A stale stamp triggers exactly one full pass per process...
set_setting('last_cleanup', (string)(time() - 7200));
$before = (int)$db->query("SELECT value FROM settings WHERE key_name = 'last_cleanup'")->fetchColumn();
run_cleanup_if_due(1.0);
$after = (int)$db->query("SELECT value FROM settings WHERE key_name = 'last_cleanup'")->fetchColumn();
T::ok('due cleanup stamps fresh time and sweeps', $after > $before);

// ...and the process-level guard makes every later visit a no-op.
run_cleanup_if_due(1.0);
$again = (int)$db->query("SELECT value FROM settings WHERE key_name = 'last_cleanup'")->fetchColumn();
T::ok('cleanup runs at most once per process', $again === $after);

// Even a broken store cannot turn a page visit into a crash.
with_table_hidden_st('settings', function (): void {
    run_cleanup_if_due(1.0); // static guard exits long before any DB touch
    T::ok('throttled cleanup ignores unreadable settings', true);
});

// The probability gate fires BEFORE the settings read: chance 0 must skip
// an otherwise-due sweep entirely (child process = fresh static guard).
$skip = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/_cleanup_chance.php'));
T::eq('probability gate skips the DB read', '1', trim((string)$skip));

// ...and do_cleanup itself answers with a count, never throws.
T::ok('do_cleanup returns a count', is_int(do_cleanup()));

exit(T::done());

function with_table_hidden_st(string $table, callable $fn): mixed {
    $bak = $table . '_st_bak';
    $dbX = get_db();
    $dbX->exec("RENAME TABLE {$table} TO {$bak}");
    try {
        return $fn();
    } finally {
        $dbX->exec("RENAME TABLE {$bak} TO {$table}");
    }
}
