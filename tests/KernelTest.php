<?php
declare(strict_types=1);

// KernelTest — the includes/kernel.php service manifest.
//
// - Requiring the kernel twice is safe (idempotency guard, no
//   "already defined" fatals, no warnings under the test error handler).
// - Every service file directly under includes/ is loaded by the kernel,
//   with one callable smoke-checked per service.
// - Regression guard for the header-sprawl cleanup: every admin entry page
//   pulls services only via the kernel. The two view partials that must
//   also work standalone (sidebar.php, osm_monit.php) keep their single
//   i18n require and are the only allowed exception.

require_once __DIR__ . '/bootstrap.php';

$root = dirname(__DIR__);

// ── Idempotent load ─────────────────────────────────────────────────────────
require_once $root . '/includes/kernel.php';
require_once $root . '/includes/kernel.php'; // second load must be a no-op
T::ok('kernel guard defined', defined('DDMGMT_KERNEL') && DDMGMT_KERNEL === true);

// ── Manifest completeness: every top-level service file is loaded ──────────
$loaded = [];
foreach (get_included_files() as $f) {
    $loaded[strtolower(str_replace('\\', '/', (string)realpath($f)))] = true;
}
$services = [];
foreach (glob($root . '/includes/*.php') as $f) {
    if (basename($f) === 'kernel.php') {
        continue; // the loader, not a service
    }
    $services[] = strtolower(str_replace('\\', '/', (string)realpath($f)));
}
T::ok('service files found', count($services) === 14);
foreach ($services as $s) {
    T::ok('kernel loads ' . basename($s), isset($loaded[$s]));
}

// ── One callable per service ────────────────────────────────────────────────
foreach ([
    'logger'      => 'app_log',
    'db'          => 'get_db',
    'net'         => 'get_client_ip',
    'settings'    => 'get_setting',
    'i18n'        => 't',
    'auth'        => 'require_admin',
    'crypto'      => 'encrypt_secret',
    'totp'        => 'totp_verify',
    'audit'       => 'audit',
    'analytics'   => 'log_event',
    'order_state' => 'order_delete_atomic',
    'proxy'       => 'osm_proxy_pool',
    'cleanup'     => 'run_cleanup_if_due',
    'wipe'        => 'do_panic_wipe',
] as $service => $fn) {
    T::ok("service $service exposes $fn()", function_exists($fn));
}

// ── Admin pages pull includes only via the kernel ───────────────────────────
$partials = ['sidebar.php' => true, 'totp_banner.php' => true, 'osm_monit.php' => true];
$checked = 0;
foreach (glob($root . '/admin/*.php') as $f) {
    $name = basename($f);
    if (isset($partials[$name])) {
        continue;
    }
    $src = (string)file_get_contents($f);
    $checked++;
    T::ok("$name requires kernel", str_contains($src, 'includes/kernel.php'));
    $stray = [];
    foreach (explode("\n", $src) as $line) {
        if (preg_match('/\b(require|include)(_once)?\b/', $line)
            && str_contains($line, '/includes/')
            && !str_contains($line, 'kernel.php')) {
            $stray[] = trim($line);
        }
    }
    T::ok("$name has no direct includes pulls", $stray === []);
}
T::ok('admin entry pages scanned', $checked === 32);

exit(T::done());
