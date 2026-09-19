<?php
declare(strict_types=1);

// ── Host capabilities ────────────────────────────────────────────────────────
// The app must run on free shared hosting: no Docker, often no cron, no exec /
// proc_open, no CLI PHP, no way to set environment variables. Everything that
// needs one of those asks THIS file whether it is there and degrades on its
// own when it is not:
//
//   no cron            → the pseudo-cron runs the hourly maintenance from page
//                        visits (includes/cleanup.php)
//   no exec / CLI      → background jobs (proxy healer) run inline after the
//                        response, under a time budget; map-zone downloads,
//                        which cannot, are refused with a clear message
//   no cURL            → proxy routing cannot work, so it is not applied and
//                        OSM requests go direct (Settings says so)
//   no env variables   → every DDMGMT_* switch can also be a constant in
//                        config.php (host_flag)
//
// Nothing here has side effects; every probe can be overridden by a test.

// A yes/no deployment switch: environment variable first (Docker, systemd,
// SetEnv), then a constant of the same name in config.php (shared hosting),
// then the default. "0", "false", "off" and "no" are off; anything else is on.
function host_flag(string $name, bool $default = true): bool {
    $v = getenv($name);
    if ($v === false || $v === '') {
        if (!defined($name)) {
            return $default;
        }
        $v = constant($name); // a config.php constant may legitimately be false
    }
    if (is_bool($v)) {
        return $v;
    }
    if ($v === null || $v === '') {
        return $default;
    }
    return !in_array(strtolower(trim((string)$v)), ['0', 'false', 'off', 'no'], true);
}

// Test seam: force probe answers ('exec', 'proc_open', 'curl', 'linux', 'cli').
/** @param array<string,mixed>|null $set */
function host_override(?array $set = null, bool $reset = false): array {
    static $o = [];
    if ($reset) {
        $o = [];
    } elseif ($set !== null) {
        $o = $set + $o;
    }
    return $o;
}

// function_exists() already answers false for names in disable_functions on
// current PHP, but a hardened host can also shadow them via an extension —
// check the ini list as well.
function host_function_usable(string $fn): bool {
    if (!function_exists($fn)) {
        return false;
    }
    $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
    return !in_array($fn, $disabled, true);
}

function host_is_linux(): bool {
    return (bool)(host_override()['linux'] ?? (PHP_OS_FAMILY === 'Linux'));
}

function host_can_exec(): bool {
    return (bool)(host_override()['exec'] ?? host_function_usable('exec'));
}

function host_can_proc_open(): bool {
    return (bool)(host_override()['proc_open'] ?? host_function_usable('proc_open'));
}

function host_has_curl(): bool {
    return (bool)(host_override()['curl'] ?? (extension_loaded('curl') && function_exists('curl_init')));
}

// A php the detached jobs can run under. PHP_BINARY is only runnable from the
// CLI SAPI: under mod_php it is empty (or the Apache binary) and under FPM it
// is php-fpm, so a detached `$PHP_BINARY script &` would die silently while
// the admin is told the job started. Fall back to the CLI next to the install.
function host_php_cli(): ?string {
    $o = host_override();
    if (array_key_exists('cli', $o)) {
        return is_string($o['cli']) ? $o['cli'] : null;
    }
    $candidates = [];
    // constant(): PHPStan knows PHP_BINARY only as a non-empty string, but
    // under mod_php it really is '' — the case this guard exists for.
    $running = (string)constant('PHP_BINARY');
    if (PHP_SAPI === 'cli' && $running !== '') {
        $candidates[] = $running;
    }
    $candidates[] = PHP_BINDIR . '/php';
    $candidates[] = '/usr/local/bin/php';
    $candidates[] = '/usr/bin/php';
    foreach ($candidates as $bin) {
        if (@is_file($bin) && @is_executable($bin)) {
            return $bin;
        }
    }
    return null;
}

// Can a job be started detached (`php script &`) from a web request?
function host_can_detach(): bool {
    return host_is_linux() && host_can_exec() && host_php_cli() !== null;
}

// A directory the app can write to — or create: data/ and tiles/ do not exist
// until first use, so the nearest existing ancestor decides.
function host_dir_writable(string $dir): bool {
    while (!is_dir($dir)) {
        $parent = dirname($dir);
        if ($parent === $dir) {
            return false;
        }
        $dir = $parent;
    }
    return is_writable($dir);
}

// What the Settings → Hosting panel lists: [id, status, note]. Status is
// 'ok', 'limited' (works, differently) or 'unavailable' (feature is off).
/** @return list<array{id:string,status:string,note:string}> */
function host_capabilities(): array {
    $root = dirname(__DIR__);
    $rows = [];

    $rows[] = ['id' => 'curl', 'status' => host_has_curl() ? 'ok' : 'unavailable', 'note' => ''];
    $rows[] = ['id' => 'exec', 'status' => (host_can_exec() && host_can_proc_open()) ? 'ok' : 'unavailable', 'note' => ''];
    $rows[] = ['id' => 'jobs', 'status' => host_can_detach() ? 'ok' : 'limited', 'note' => ''];

    $last = (int)get_setting('last_cleanup', '0');
    $ago = $last > 0 ? time() - $last : null;
    $rows[] = [
        'id'     => 'sweep',
        'status' => ($ago !== null && $ago < 7200) ? 'ok' : 'limited',
        'note'   => $ago === null ? '' : (string)max(1, (int)round($ago / 60)),
    ];

    $bad = [];
    foreach (['logs', 'uploads', 'cache', 'data', 'tiles'] as $d) {
        if (!host_dir_writable($root . '/' . $d)) {
            $bad[] = $d . '/';
        }
    }
    $rows[] = ['id' => 'dirs', 'status' => $bad === [] ? 'ok' : 'unavailable', 'note' => implode(', ', $bad)];

    $rows[] = ['id' => 'zones', 'status' => maps_downloads_supported() ? 'ok' : 'unavailable', 'note' => ''];
    return $rows;
}
