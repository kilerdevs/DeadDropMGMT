<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';

function get_settings(): array {
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    try {
        $rows  = get_db()->query('SELECT key_name, value FROM settings')->fetchAll();
        $cache = [];
        foreach ($rows as $r) {
            $cache[$r['key_name']] = $r['value'];
        }
    } catch (Exception $e) {
        log_err('Settings load failed: ' . $e->getMessage());
        $cache = [];
    }
    return $cache;
}

function get_setting(string $key, string $default = ''): string {
    return get_settings()[$key] ?? $default;
}

function set_setting(string $key, string $value): void {
    get_db()->prepare(
        'INSERT INTO settings (key_name, value, label)
         VALUES (?, ?, "")
         ON DUPLICATE KEY UPDATE value = VALUES(value)'
    )->execute([$key, $value]);
}

// Helpers used throughout the application
function site_name(): string {
    $s = get_setting('site_name', '');
    if ($s !== '') return $s;
    return defined('SITE_NAME') ? SITE_NAME : 'MGT';
}

function order_ttl_hours(): int {
    return max(1, (int)get_setting('order_ttl_hours', '24'));
}

function rl_max(): int {
    return max(1, (int)get_setting('rate_limit_max', (string)RATE_LIMIT_MAX));
}

function rl_window_seconds(): int {
    return max(60, (int)get_setting('rate_limit_window_min', (string)(RATE_LIMIT_WINDOW / 60)) * 60);
}

function admin_session_seconds(): int {
    return max(1800, (int)round((float)get_setting('admin_session_hours', '4') * 3600));
}

function max_photo_bytes(): int {
    return (int)(max(0.1, (float)get_setting('max_photo_mb', '2')) * 1024 * 1024);
}

function analytics_enabled(): bool {
    return get_setting('analytics_enabled', '1') === '1';
}

function default_lang(): string {
    return get_setting('default_lang', 'en');
}

// Cosmetic "ISO compliant" footer shown on public pages. Off by default —
// it is a marketing claim, not a fact about this software.
function compliance_note_enabled(): bool {
    return get_setting('compliance_note_enabled', '0') === '1';
}

// Route admin-panel OpenStreetMap traffic (tiles, geocoding) through the
// osm_proxies pool. Off by default — with no proxies configured it would
// only add failure modes.
function osm_proxy_enabled(): bool {
    return get_setting('osm_proxy_enabled', '0') === '1';
}

function extend_hours_options(): array {
    $raw = get_setting('extend_hours_options', '24,48,72');
    $opts = [];
    foreach (explode(',', $raw) as $h) {
        $n = (int)trim($h);
        if ($n > 0) $opts[] = $n;
    }
    return $opts ?: [24, 48, 72];
}

// Format seconds as "Xh Ym Zs"
function format_countdown(int $seconds): string {
    if ($seconds <= 0) {
        require_once __DIR__ . '/i18n.php';
        return t('common.expired');
    }
    $h = intdiv($seconds, 3600);
    $m = intdiv($seconds % 3600, 60);
    $s = $seconds % 60;
    if ($h > 0) return "{$h}h {$m}m {$s}s";
    if ($m > 0) return "{$m}m {$s}s";
    return "{$s}s";
}
